import { describe, expect, test } from "bun:test";
import { buildCommandContext, stripUrlCredentials } from "../src/context/command-context.js";
import { parseSanctioned } from "../src/rules/uploads.js";
import type { GitRunner } from "../src/context/script-provenance.js";
import { buildRequest } from "../src/classifier/jev-client.js";

const sanctioned = parseSanctioned(["forge.example.ts.net"]);

/** A git that knows one repository at `root`, its remotes, and which paths are tracked. */
function fakeRepo(root: string, remotes: Record<string, string>, tracked: string[] = []): GitRunner {
  return (args, cwd) => {
    const inRepo = cwd === root || cwd.startsWith(root + "/");
    if (!inRepo) return { status: 128, stdout: "" };
    if (args[0] === "rev-parse" && args[1] === "--show-toplevel") return { status: 0, stdout: root };
    if (args[0] === "remote" && args.length === 1) return { status: 0, stdout: Object.keys(remotes).join("\n") };
    if (args[0] === "remote" && args[1] === "get-url") {
      const url = remotes[args[args.length - 1]];
      return url ? { status: 0, stdout: url } : { status: 2, stdout: "" };
    }
    if (args[0] === "ls-files") {
      const p = args[args.length - 1];
      return { status: 0, stdout: tracked.filter((t) => t === p || t.startsWith(p + "/")).join("\n") };
    }
    return { status: 1, stdout: "" };
  };
}

describe("buildCommandContext", () => {
  const git = fakeRepo("/home/dev/src/app", {
    origin: "https://dev:s3cr3t-token@forge.example.ts.net/owner/app.git",
    upstream: "git@github.com:someone/app.git",
  }, ["/home/dev/src/app/data/seed.json"]);

  test("names the repository, its remotes with credentials stripped, and which are sanctioned", () => {
    const ctx = buildCommandContext("git status", "/home/dev/src/app", { git, sanctioned });
    expect(ctx).toEqual({
      cwd: "/home/dev/src/app",
      in_git_worktree: true,
      repo_root: "/home/dev/src/app",
      remotes: {
        origin: { url: "https://forge.example.ts.net/owner/app.git", sanctioned: true },
        upstream: { url: "git@github.com:someone/app.git", sanctioned: false },
      },
    });
  });

  test("says where each deleted path lands, and whether git tracks it", () => {
    const ctx = buildCommandContext("rm -rf ./data node_modules /var/lib/mysql && rm -rf /tmp/scratch", "/home/dev/src/app", { git, sanctioned });
    expect(ctx.destructive_targets).toEqual([
      { command: "rm", path: "/home/dev/src/app/data", inside: ["repo"], tracked: true },
      { command: "rm", path: "/home/dev/src/app/node_modules", inside: ["repo", "build_or_cache"], tracked: false },
      { command: "rm", path: "/var/lib/mysql", inside: ["not_scratch"] },
      { command: "rm", path: "/tmp/scratch", inside: ["tmp"] },
    ]);
  });

  test("the repository itself and its .git are not scratch inside it", () => {
    const ctx = buildCommandContext("rm -rf .git && cd .. && rm -rf app", "/home/dev/src/app", { git, sanctioned });
    expect(ctx.destructive_targets?.map((t) => t.inside)).toEqual([["repo_git_dir"], ["repo_root_itself"]]);
    const self = buildCommandContext("rm -rf /home/dev/src/app", "/home/dev/src/app", { git, sanctioned });
    expect(self.destructive_targets?.[0].inside).toEqual(["repo_root_itself"]);
  });

  test("a build-looking name outside a repository is not build output", () => {
    const ctx = buildCommandContext("sudo rm -rf /usr/bin/python3", "/home/dev", { git, sanctioned });
    expect(ctx.destructive_targets?.[0].inside).toEqual(["not_scratch"]);
    expect(ctx.in_git_worktree).toBe(false);
  });

  test("follows cd and variables, reads git clean and find -delete, and skips flag values", () => {
    const ctx = buildCommandContext('D=/home/dev/src/app/dist; cd "$D" && truncate -s 0 app.log; git clean -fdx; find build -name "*.o" -delete', "/home/dev", { git, sanctioned });
    expect(ctx.destructive_targets?.map((t) => [t.command, t.path])).toEqual([
      ["truncate", "/home/dev/src/app/dist/app.log"],
      ["git clean", "/home/dev/src/app/dist"],
      ["find", "/home/dev/src/app/dist/build"],
    ]);
  });

  test("anything git cannot answer is left out, not guessed", () => {
    const broken: GitRunner = () => ({ status: 1, stdout: "" });
    expect(buildCommandContext("ls", "/somewhere", { git: broken })).toEqual({ cwd: "/somewhere", in_git_worktree: false });
    expect(buildCommandContext("ls", undefined, { git: broken })).toEqual({});
  });

  test("stripUrlCredentials", () => {
    expect(stripUrlCredentials("https://u:p@host/x.git")).toBe("https://host/x.git");
    expect(stripUrlCredentials("git@github.com:o/r.git")).toBe("git@github.com:o/r.git");
  });

  test("rides in Jev's state, sanitised like the command", () => {
    const ctx = buildCommandContext("rm -rf ./data", "/home/dev/src/app", { git, sanctioned });
    const body = buildRequest("rm -rf ./data", undefined, {}, 2000, { context: { ...ctx, cwd: "/home/dev/API_TOKEN=abcdefghijklmnop" } }) as any;
    expect(body.state.context.remotes.origin.sanctioned).toBe(true);
    expect(body.state.context.cwd).not.toContain("abcdefghijklmnop");
  });
});
