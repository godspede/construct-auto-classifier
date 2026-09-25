import { describe, it, expect } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { findReferencedFiles } from "../src/context/file-references.js";

describe("findReferencedFiles", () => {
  it("detects files passed via flags like -f and --body-file", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ref-test-"));
    try {
      const file1 = path.join(tmp, "notes.md");
      const file2 = path.join(tmp, "query.sql");
      fs.writeFileSync(file1, "# Hello notes\nLine 2", "utf-8");
      fs.writeFileSync(file2, "SELECT * FROM users;", "utf-8");

      const cmd = `forgectl issue comment --body-file ${file1} && psql -f ${file2}`;
      const found = findReferencedFiles(cmd, tmp);

      expect(found.length).toBe(2);
      expect(found[0]?.path).toBe(file1);
      expect(found[0]?.content).toBe("# Hello notes\nLine 2");
      expect(found[1]?.path).toBe(file2);
      expect(found[1]?.content).toBe("SELECT * FROM users;");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("detects files by recognised extension without flags", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ref-test-"));
    try {
      const patch = path.join(tmp, "feature.patch");
      fs.writeFileSync(patch, "diff --git a/x b/x\n+new line", "utf-8");

      const cmd = `git apply ${patch}`;
      const found = findReferencedFiles(cmd, tmp);

      expect(found.length).toBe(1);
      expect(found[0]?.path).toBe(patch);
      expect(found[0]?.content).toContain("diff --git");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("ignores non-existent or binary files, and withholds a protected one", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ref-test-"));
    try {
      const binFile = path.join(tmp, "test.bin.sql");
      fs.writeFileSync(binFile, Buffer.from([0x00, 0x01, 0x02, 0x03]));
      const gateDir = path.join(tmp, ".config", "auto-classifier");
      fs.mkdirSync(gateDir, { recursive: true });
      fs.writeFileSync(path.join(gateDir, "config.jsonc"), '{"dummy": "gate setting"}');

      const cmd = `cat missing.sql ${binFile} ${path.join(gateDir, "config.jsonc")}`;
      const found = findReferencedFiles(cmd, tmp);

      expect(found.length).toBe(1);
      expect(found[0]?.content).toContain("withheld");
      expect(found[0]?.content).not.toContain("gate setting");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("truncates content exceeding maxChars", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ref-test-"));
    try {
      const bigFile = path.join(tmp, "big.diff");
      fs.writeFileSync(bigFile, "a".repeat(100), "utf-8");

      const cmd = `git apply ${bigFile}`;
      const found = findReferencedFiles(cmd, tmp, { maxChars: 40 });

      expect(found.length).toBe(1);
      expect(found[0]?.content.length).toBe(40);
      expect(found[0]?.truncated).toBe(true);
      expect(found[0]?.originalLength).toBe(100);
      // A referenced file is data, never the program the command runs.
      expect(found[0]?.executed).toBe(false);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
