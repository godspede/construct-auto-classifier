import { describe, it, expect } from "bun:test";
import { AutoClassifier } from "../src/index.js";
import { StateManager } from "../src/state/state-manager.js";
import { createOpenCodePlugin, fileToolTargets } from "../src/adapters/opencode.js";
import { FakeLlm } from "./helpers/fake-llm.js";
import { tmpStateDir } from "./helpers/tmp-state.js";
import { testConfig } from "./helpers/config.js";

function hooks() {
  const config = testConfig();
  const state = new StateManager(config.policy.slidingWindowMs, config.policy.consecutiveThreshold, tmpStateDir());
  const classifier = new AutoClassifier(config, { classifier: new FakeLlm(), stateManager: state });
  return createOpenCodePlugin(classifier, { pluginsDir: tmpStateDir() })({ client: {} } as any) as any;
}
const call = (h: any, tool: string, args: object) => h["tool.execute.before"]({ tool, sessionID: "ses_1", callID: "c1" }, { args });

describe("opencode adapter: file tools", () => {
  it("refuses an edit to the gate's own config", async () => {
    await expect(call(hooks(), "edit", { filePath: "/home/z/.config/auto-classifier/config.jsonc" })).rejects.toThrow(/safety classifier itself/);
  });
  it("refuses a write over the installed plugin", async () => {
    await expect(call(hooks(), "write", { filePath: "/home/z/.config/opencode/plugins/auto-classifier.js", content: "" })).rejects.toThrow();
  });
  it("refuses a patch that touches the gate anywhere in it", async () => {
    const patchText = "*** Begin Patch\n*** Update File: src/a.ts\n@@\n-a\n+b\n*** Update File: /home/z/.config/auto-classifier/local.jsonc\n*** End Patch";
    await expect(call(hooks(), "patch", { patchText })).rejects.toThrow();
  });
  it("leaves ordinary edits to opencode's own permissions", async () => {
    await call(hooks(), "edit", { filePath: "/work/app/src/a.ts" });
    await call(hooks(), "write", { filePath: "/work/app/notes.md", content: "x" });
  });
});

describe("fileToolTargets", () => {
  it("reads filePath and every file a patch names", () => {
    expect(fileToolTargets("edit", { filePath: "/a" })).toEqual(["/a"]);
    expect(fileToolTargets("patch", { patchText: "*** Add File: b\n*** Delete File: c\n*** Update File: d\n*** Move to: e" })).toEqual(["b", "c", "d", "e"]);
    expect(fileToolTargets("read", {})).toEqual([]);
  });
});
