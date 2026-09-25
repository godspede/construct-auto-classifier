import { describe, it, expect } from "bun:test";
import { buildSystemPrompt, buildUserPrompt } from "../src/classifier/prompt.js";
import { buildRequest } from "../src/classifier/jev-client.js";
import { loadConfig } from "../src/config.js";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

describe("instructionsAppend", () => {
  it("appends instructions to buildSystemPrompt when provided", () => {
    const prompt = buildSystemPrompt("All git commit and push operations are safe.");
    expect(prompt).toContain("Additional instructions:");
    expect(prompt).toContain("All git commit and push operations are safe.");
    expect(prompt).toContain("pushing to a sanctioned remote, main included");
  });

  it("appends instructions to Jev verdict question in buildRequest", () => {
    const cfg = {
      instructionsAppend: "Project forge operations are routine and safe.",
    };
    const req = buildRequest("git push origin feat/x", undefined, cfg) as any;
    expect(req.questions.verdict.instructions).toContain("Additional instructions: Project forge operations are routine and safe.");
    // Only in the question's instructions, which both options are read under:
    // the text may ask for a deny as easily as an allow, so it describes
    // neither option.
    expect(req.questions.verdict.criteria.allow).not.toContain("Project forge operations");
    expect(req.questions.verdict.criteria.deny).not.toContain("Project forge operations");
  });

  it("leaves the Jev request exactly as certified when there is nothing to append", () => {
    const plain = buildRequest("git push origin feat/x", undefined, {}) as any;
    const empty = buildRequest("git push origin feat/x", undefined, { instructionsAppend: "" }) as any;
    expect(empty).toEqual(plain);
  });

  it("formats attachedFiles in buildUserPrompt", () => {
    const userPrompt = buildUserPrompt("git apply test.patch", {
      path: "test.patch",
      content: "",
      attachedFiles: [
        { path: "test.patch", content: "+hello world", truncated: false, originalLength: 12 },
      ],
    });
    expect(userPrompt).toContain('ATTACHED FILE CONTEXT: "test.patch"');
    expect(userPrompt).toContain("+hello world");
  });

  it("parses policy.instructionsAppend in loadConfig", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cfg-test-"));
    try {
      const cfgPath = path.join(tmp, "config.jsonc");
      fs.writeFileSync(
        cfgPath,
        JSON.stringify({
          policy: {
            instructionsAppend: "Custom instruction line.",
          },
        }),
        "utf-8"
      );

      const loaded = loadConfig(cfgPath);
      expect(loaded.policy.instructionsAppend).toBe("Custom instruction line.");
      expect(loaded.jev.instructionsAppend).toBe("Custom instruction line.");
      expect(loaded.llm.instructionsAppend).toBe("Custom instruction line.");
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
