import { describe, it, expect } from "bun:test";
import { parsePatchTargets } from "../src/rules/patch.js";

describe("parsePatchTargets", () => {
  it("extracts every target from the OpenAI apply_patch envelope", () => {
    const patch = ["*** Begin Patch", "*** Update File: src/x.ts", "@@", "-old", "+new", "*** End Patch"].join("\n");
    expect(parsePatchTargets(patch)).toEqual(["src/x.ts"]);
  });

  it("extracts every file in a multi-file apply_patch envelope, including a move", () => {
    const patch = [
      "*** Begin Patch",
      "*** Add File: src/new.ts",
      "+hello",
      "*** Update File: src/old.ts",
      "*** Move to: src/renamed.ts",
      "@@",
      "-a",
      "+b",
      "*** Delete File: src/gone.ts",
      "*** End Patch",
    ].join("\n");
    expect(new Set(parsePatchTargets(patch))).toEqual(new Set(["src/new.ts", "src/old.ts", "src/renamed.ts", "src/gone.ts"]));
  });

  it("extracts targets from a git-style unified diff header", () => {
    const patch = ["diff --git a/src/x.ts b/src/x.ts", "index abc..def 100644", "--- a/src/x.ts", "+++ b/src/x.ts", "@@ -1 +1 @@", "-old", "+new"].join("\n");
    expect(new Set(parsePatchTargets(patch))).toEqual(new Set(["src/x.ts"]));
  });

  it("extracts targets from a bare unified diff with no a/b prefix", () => {
    const patch = ["--- src/x.ts", "+++ src/x.ts", "@@ -1 +1 @@", "-old", "+new"].join("\n");
    expect(parsePatchTargets(patch)).toEqual(["src/x.ts"]);
  });

  it("does not treat /dev/null as a target (a pure add or delete)", () => {
    const added = ["--- /dev/null", "+++ b/src/new.ts", "@@ -0,0 +1 @@", "+hello"].join("\n");
    expect(parsePatchTargets(added)).toEqual(["src/new.ts"]);

    const deleted = ["--- a/src/gone.ts", "+++ /dev/null", "@@ -1 +0,0 @@", "-bye"].join("\n");
    expect(parsePatchTargets(deleted)).toEqual(["src/gone.ts"]);
  });

  it("returns null when nothing recognizable is found", () => {
    expect(parsePatchTargets("not a patch at all, just some prose")).toBeNull();
    expect(parsePatchTargets("")).toBeNull();
  });
});
