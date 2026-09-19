import { describe, it, expect } from "bun:test";
import { AutoClassifier } from "../src/index.js";
import { StateManager } from "../src/state/state-manager.js";
import { handleAgyInput } from "../src/adapters/agy.js";
import type { AcceptTarget } from "../src/adapters/agy-accept.js";
import { FakeLlm } from "./helpers/fake-llm.js";
import { tmpStateDir } from "./helpers/tmp-state.js";
import { testConfig } from "./helpers/config.js";

function classifier(llm: FakeLlm) {
  const config = testConfig();
  return new AutoClassifier(config, {
    classifier: llm,
    stateManager: new StateManager(config.policy.slidingWindowMs, config.policy.consecutiveThreshold, tmpStateDir()),
  });
}
const prompts = () => null;
const autoApproves = () => "agy was started with --dangerously-skip-permissions";
function watcher() {
  const started: Array<string | AcceptTarget> = [];
  return { started, onAllow: (t: string | AcceptTarget) => (started.push(t), true) };
}
// The payload shape agy 1.2.7 sends a PreToolUse hook for its file tools.
const fileCall = (name: string, target: string, workspacePaths = ["/work/app"]) =>
  JSON.stringify({ toolCall: { name, args: { TargetFile: target, CodeContent: "x" } }, conversationId: "conv-1", workspacePaths });

describe("agy adapter: file tools", () => {
  it("allows a write inside the workspace without asking the model, and watches for its prompt", async () => {
    const llm = new FakeLlm();
    const w = watcher();
    const out = await handleAgyInput(fileCall("write_to_file", "/work/app/notes.txt"), classifier(llm), prompts, w.onAllow);
    expect(out).toEqual({ decision: "allow" });
    expect(w.started).toEqual([{ kind: "file", path: "/work/app/notes.txt" }]);
    expect(llm.calls.length).toBe(0);
  });
  it("covers replace_file_content too", async () => {
    const w = watcher();
    const out = await handleAgyInput(fileCall("replace_file_content", "/work/app/src/a.ts"), classifier(new FakeLlm()), prompts, w.onAllow);
    expect(out.decision).toBe("allow");
    expect(w.started).toHaveLength(1);
  });
  it("escalates a write outside the workspace, with the reason on the prompt and no watcher", async () => {
    const w = watcher();
    const out = await handleAgyInput(fileCall("write_to_file", "/home/z/elsewhere.txt"), classifier(new FakeLlm()), prompts, w.onAllow);
    expect(out.decision).toBe("force_ask");
    expect(out.reason).toContain("outside the session's workspace");
    expect(w.started).toEqual([]);
  });
  it("escalates a write into .git", async () => {
    const out = await handleAgyInput(fileCall("write_to_file", "/work/app/.git/hooks/pre-commit"), classifier(new FakeLlm()), prompts, watcher().onAllow);
    expect(out.decision).toBe("force_ask");
  });
  it("denies a write to the gate's own config", async () => {
    const out = await handleAgyInput(
      fileCall("write_to_file", "/home/z/.config/auto-classifier/config.jsonc", ["/home/z"]),
      classifier(new FakeLlm()),
      prompts,
      watcher().onAllow
    );
    expect(out.decision).toBe("deny");
  });
  it("turns an escalated write into a denial when agy would approve it itself", async () => {
    const out = await handleAgyInput(fileCall("write_to_file", "/home/z/elsewhere.txt"), classifier(new FakeLlm()), autoApproves, watcher().onAllow);
    expect(out.decision).toBe("deny");
    expect(out.reason).toContain("--dangerously-skip-permissions");
  });
  it("still ignores tools that write nothing", async () => {
    const out = await handleAgyInput(
      JSON.stringify({ toolCall: { name: "view_file", args: { AbsolutePath: "/etc/hosts" } }, workspacePaths: ["/work/app"] }),
      classifier(new FakeLlm()),
      prompts,
      watcher().onAllow
    );
    expect(out).toEqual({ decision: "allow" });
  });
});
