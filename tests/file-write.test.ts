import { describe, it, expect } from "bun:test";
import { judgeFileWrite } from "../src/rules/file-write.js";

describe("judgeFileWrite", () => {
  const ws = ["/work/app"];

  it("allows an ordinary file inside the workspace", () => {
    expect(judgeFileWrite("/work/app/src/index.ts", ws, "linux")).toEqual({ decision: "allow" });
  });
  it("resolves a relative target against the workspace", () => {
    expect(judgeFileWrite("src/index.ts", ws, "linux")).toEqual({ decision: "allow" });
  });
  it("escalates a write outside the workspace, naming where", () => {
    const v = judgeFileWrite("/home/z/notes.txt", ws, "linux");
    expect(v.decision).toBe("escalate");
    expect(v.decision === "escalate" && v.reason).toContain("outside the session's workspace");
  });
  it("escalates a relative path that climbs out of the workspace", () => {
    expect(judgeFileWrite("../other/x.txt", ws, "linux").decision).toBe("escalate");
  });
  it("does not treat a sibling that shares a prefix as inside", () => {
    expect(judgeFileWrite("/work/app-evil/x.txt", ws, "linux").decision).toBe("escalate");
  });
  it("escalates with no workspace to be inside of", () => {
    expect(judgeFileWrite("/work/app/x.txt", [], "linux").decision).toBe("escalate");
  });
  it("escalates the empty target", () => {
    expect(judgeFileWrite("", ws, "linux").decision).toBe("escalate");
  });

  for (const sensitive of [
    ".git/hooks/pre-commit",
    ".git/config",
    ".agents/hooks.json",
    ".gemini/settings.json",
    ".claude/settings.json",
    ".opencode/plugins/x.js",
    "opencode.json",
    ".mcp.json",
    ".env",
    ".env.local",
    ".envrc",
    ".github/workflows/ci.yml",
    ".gitea/workflows/ci.yml",
    ".githooks/pre-push",
  ]) {
    it(`escalates ${sensitive} inside the workspace`, () => {
      expect(judgeFileWrite(`/work/app/${sensitive}`, ws, "linux").decision).toBe("escalate");
    });
  }
  it("allows a file that only looks like a sensitive one", () => {
    expect(judgeFileWrite("/work/app/docs/env.md", ws, "linux")).toEqual({ decision: "allow" });
    expect(judgeFileWrite("/work/app/gitconfig.example", ws, "linux")).toEqual({ decision: "allow" });
  });

  it("denies the gate's own files, even inside the workspace", () => {
    const v = judgeFileWrite("/home/z/.config/auto-classifier/config.jsonc", ["/home/z"], "linux");
    expect(v.decision).toBe("deny");
  });
  it("denies a relative path that resolves into the gate's files", () => {
    expect(judgeFileWrite("../.config/auto-classifier/local.jsonc", ["/home/z/app"], "linux").decision).toBe("deny");
  });

  describe("on Windows", () => {
    const win = [String.raw`D:\tmp\gate-test`];
    it("matches agy's forward-slash TargetFile to a backslash workspace, case-insensitively", () => {
      expect(judgeFileWrite("D:/tmp/gate-test/a.txt", win, "win32")).toEqual({ decision: "allow" });
      expect(judgeFileWrite("d:/TMP/Gate-Test/a.txt", ["D:/tmp/gate-test"], "win32")).toEqual({ decision: "allow" });
    });
    it("escalates another drive", () => {
      expect(judgeFileWrite("C:/Users/z/a.txt", win, "win32").decision).toBe("escalate");
    });
    it("denies the gate's own config", () => {
      expect(judgeFileWrite(String.raw`C:\Users\z\.config\auto-classifier\local.jsonc`, [String.raw`C:\Users\z`], "win32").decision).toBe("deny");
    });
  });
});
