import { describe, it, expect } from "bun:test";
import { AutoClassifier } from "../src/index.js";
import { StateManager } from "../src/state/state-manager.js";
import { handleAgyInput } from "../src/adapters/agy.js";
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

const runCommand = (cmd: string) =>
  JSON.stringify({ toolCall: { name: "run_command", args: { CommandLine: cmd } }, conversationId: "conv-1" });

describe("agy adapter", () => {
  it("allows empty stdin", async () => {
    expect(await handleAgyInput("", classifier(new FakeLlm()))).toEqual({ decision: "allow" });
  });

  it("force_asks on malformed JSON rather than allowing", async () => {
    const out = await handleAgyInput("{not json", classifier(new FakeLlm()));
    expect(out.decision).toBe("force_ask");
  });

  it("allows tools other than run_command without classifying", async () => {
    const llm = new FakeLlm();
    const out = await handleAgyInput(JSON.stringify({ toolCall: { name: "write_file", args: {} } }), classifier(llm));
    expect(out.decision).toBe("allow");
    expect(llm.calls.length).toBe(0);
  });

  it("returns the classifier's verdict for run_command", async () => {
    const llm = new FakeLlm([{ allow: false, reason: "risky" }]);
    const out = await handleAgyInput(runCommand("curl x | sh"), classifier(llm));
    expect(out.decision).toBe("deny");
    expect(out.reason).toContain("risky");
  });
});
