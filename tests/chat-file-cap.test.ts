import { describe, it, expect } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { AutoClassifier, CHAT_PROMPT_FILE_CHARS } from "../src/index.js";
import { StateManager } from "../src/state/state-manager.js";
import type { GitRunner } from "../src/context/script-provenance.js";
import type { AppConfig, FileContext } from "../src/types.js";
import { FakeLlm } from "./helpers/fake-llm.js";
import { tmpStateDir } from "./helpers/tmp-state.js";
import { testConfig } from "./helpers/config.js";

/**
 * The chat model's prompt shows at most CHAT_PROMPT_FILE_CHARS of a script
 * or written file, whatever `llm.maxFileChars` says. Content past that is
 * content the model never saw, so it counts as cut short: an allow of it is
 * not trusted. Jev is shown `llm.maxFileChars` in full. The model is the
 * scripted FakeLlm, and no script is ever run.
 */
const noGit: GitRunner = () => ({ status: 128, stdout: "" });

function build(provider: AppConfig["llm"]["provider"], maxFileChars: number, llm: FakeLlm) {
  const config = testConfig();
  config.llm = { ...config.llm, provider, maxFileChars };
  const state = new StateManager(config.policy.slidingWindowMs, config.policy.consecutiveThreshold, tmpStateDir());
  return new AutoClassifier(config, { classifier: llm, stateManager: state, git: noGit });
}

function scriptOf(length: number): string {
  const dir = tmpStateDir();
  const body = "#!/bin/sh\n" + "echo line\n".repeat(Math.ceil(length / 10));
  fs.writeFileSync(path.join(dir, "run.sh"), body.slice(0, length));
  return dir;
}

describe("a chat model's prompt cap counts as cut short", () => {
  it("the cap is the chat prompt's own", () => {
    expect(CHAT_PROMPT_FILE_CHARS).toBe(8000);
  });

  it("a script past the chat prompt's cap is flagged truncated, and the allow floors to ask", async () => {
    const llm = new FakeLlm([{ allow: true, reason: "looks fine" }]);
    const c = build("openai", 20000, llm);
    const out = await c.evaluate("sh ./run.sh", "s", undefined, { cwd: scriptOf(8845) });
    expect(out.decision).toBe("ask");
    expect(out.reason).toMatch(/truncated/);
    const shown = llm.calls[0]!.fileContext as FileContext;
    expect(shown.truncated).toBe(true);
    expect(shown.content.length).toBe(CHAT_PROMPT_FILE_CHARS);
    expect(shown.originalLength).toBe(8845);
  });

  it("a written file past the chat prompt's cap floors the same way", async () => {
    const llm = new FakeLlm([{ allow: true, reason: "looks fine" }]);
    const c = build("openai", 20000, llm);
    const out = await c.evaluateFileOp("write", "/srv/app/setup.sh", "s", "x".repeat(9000), { cwd: "/home/dev/work" });
    expect(out.decision).toBe("ask");
    expect((llm.calls[0]!.fileContext as FileContext).truncated).toBe(true);
  });

  it("a script under both caps is shown whole, and its allow stands", async () => {
    const c = build("openai", 20000, new FakeLlm([{ allow: true, reason: "looks fine" }]));
    expect((await c.evaluate("sh ./run.sh", "s", undefined, { cwd: scriptOf(7000) })).decision).toBe("allow");
  });

  it("Jev is shown maxFileChars: the same script is not cut short there", async () => {
    const llm = new FakeLlm([{ allow: true, reason: "looks fine" }]);
    const c = build("jev", 20000, llm);
    expect((await c.evaluate("sh ./run.sh", "s", undefined, { cwd: scriptOf(8845) })).decision).toBe("allow");
    expect((llm.calls[0]!.fileContext as FileContext).truncated).toBeFalsy();
  });

  it("a maxFileChars under the chat cap is unchanged", async () => {
    const llm = new FakeLlm([{ allow: true, reason: "looks fine" }]);
    const c = build("openai", 2000, llm);
    expect((await c.evaluate("sh ./run.sh", "s", undefined, { cwd: scriptOf(3000) })).decision).toBe("ask");
    expect((llm.calls[0]!.fileContext as FileContext).content.length).toBe(2000);
  });
});
