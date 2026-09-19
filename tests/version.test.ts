import { describe, it, expect } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { VERSION } from "../src/version.js";

describe("VERSION", () => {
  it("equals package.json's version", () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(import.meta.dir, "..", "package.json"), "utf-8"));
    expect(VERSION).toBe(pkg.version);
  });
});
