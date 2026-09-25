import { describe, it, expect } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { isWithinWorkspace, resolveRealPath } from "../src/rules/workspace.js";

describe("isWithinWorkspace", () => {
  it("treats a path under the workspace root as inside it, relative or absolute", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-classifier-workspace-"));
    fs.mkdirSync(path.join(dir, "src"));
    fs.writeFileSync(path.join(dir, "src", "x.ts"), "");
    expect(isWithinWorkspace("src/x.ts", dir)).toBe(true);
    expect(isWithinWorkspace(path.join(dir, "src", "x.ts"), dir)).toBe(true);
    expect(isWithinWorkspace(dir, dir)).toBe(true); // the root itself
  });

  it("treats a sibling or ancestor path as outside the workspace", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-classifier-workspace-"));
    expect(isWithinWorkspace("/etc/passwd", dir)).toBe(false);
    expect(isWithinWorkspace(path.dirname(dir), dir)).toBe(false);
    expect(isWithinWorkspace("../outside.txt", dir)).toBe(false);
  });

  it("does not need the target to exist yet -- a new file a write is about to create", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-classifier-workspace-"));
    expect(isWithinWorkspace("brand/new/file.ts", dir)).toBe(true);
    expect(isWithinWorkspace("../../etc/shadow", dir)).toBe(false);
  });

  it("resolves a symlink that escapes the workspace before comparing", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-classifier-workspace-"));
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "auto-classifier-outside-"));
    fs.writeFileSync(path.join(outside, "secret.txt"), "");
    fs.symlinkSync(outside, path.join(dir, "escape"));
    expect(isWithinWorkspace("escape/secret.txt", dir)).toBe(false);
  });
});

describe("resolveRealPath", () => {
  it("resolves an existing path exactly as fs.realpathSync would", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-classifier-workspace-"));
    expect(resolveRealPath(dir)).toBe(fs.realpathSync(dir));
  });

  it("resolves the longest existing ancestor and rejoins the rest for a path that does not exist yet", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-classifier-workspace-"));
    const target = path.join(dir, "a", "b", "c.txt");
    expect(resolveRealPath(target)).toBe(path.join(fs.realpathSync(dir), "a", "b", "c.txt"));
  });
});
