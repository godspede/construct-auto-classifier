import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

function git(args: string[], cwd: string): string {
  const r = spawnSync("git", args, { cwd, encoding: "utf-8" });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${r.stderr}`);
  return r.stdout.trim();
}

/**
 * A working clone with a bare "origin" whose main branch holds one committed
 * script. Tests then modify, add, or leave the script to exercise provenance.
 */
export function gitFixture(script = "deploy/publish.sh", content = "#!/usr/bin/env bash\necho publish\n") {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "auto-classifier-git-"));
  const bare = path.join(root, "origin.git");
  const work = path.join(root, "work");
  git(["init", "-q", "--bare", "-b", "main", bare], root);
  git(["clone", "-q", bare, work], root);
  const id = ["-c", "user.name=t", "-c", "user.email=t@t"];
  fs.mkdirSync(path.join(work, path.dirname(script)), { recursive: true });
  fs.writeFileSync(path.join(work, script), content, { mode: 0o755 });
  git(["add", "."], work);
  git([...id, "commit", "-q", "-m", "init"], work);
  git(["push", "-q", "-u", "origin", "main"], work);
  git(["remote", "set-head", "origin", "main"], work);
  return { root, work, script, abs: path.join(work, script), git: (args: string[]) => git(args, work) };
}
