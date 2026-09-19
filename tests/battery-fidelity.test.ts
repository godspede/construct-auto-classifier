import { describe, it, expect } from "bun:test";
import {
  beforeHookFieldsRead,
  eventHookFieldsRead,
  beforeHookInput,
  beforeHookOutput,
  permissionAskedEvent,
  flattenPaths,
  coversField,
  readAdapterSource,
} from "../bench/payload.js";

/**
 * The load-bearing test for the certification battery's one requirement: it
 * is worthless if the requests it drives through the classifier differ in
 * any way from opencode's own. bench/run.ts drives the real
 * `AutoClassifier` through the real `createOpenCodePlugin` using the payload
 * builders in bench/payload.ts. This test fails the moment those builders'
 * output stops carrying a field src/adapters/opencode.ts actually reads --
 * which is exactly the drift that would make the battery's verdicts mean
 * nothing, silently.
 *
 * The field list itself is not hand-copied here: beforeHookFieldsRead() and
 * eventHookFieldsRead() extract it from the adapter's own source (see
 * bench/payload.ts's NOT_A_VERDICT_FIELD for the documented, principled
 * exclusions -- containers, aliases, routing checks, a dead OR-fallback, and
 * a write-only field). If the adapter starts reading a new field, this test
 * starts requiring it with no second list to remember to update.
 */
describe("battery payload fidelity", () => {
  it("tool.execute.before's payload carries every field the adapter reads off it", () => {
    const required = beforeHookFieldsRead();
    expect(required.length).toBeGreaterThan(0); // the extraction itself must not have gone silently empty

    const input = beforeHookInput({ sessionId: "ses_1", callId: "call_1" });
    const output = beforeHookOutput("echo hi", "/work/dir");
    const paths = [...flattenPaths(input), ...flattenPaths(output)];

    for (const field of required) {
      expect(coversField(paths, field)).toBe(true);
    }

    // And pin the set itself, so a field silently dropped from the adapter
    // (shrinking `required`) is caught too, not just a field silently added.
    expect(new Set(required)).toEqual(new Set(["tool", "sessionID", "callID", "args.command", "args.workdir"]));
  });

  it("the permission.asked event payload carries every field the adapter reads off it, in both callID shapes", () => {
    const required = eventHookFieldsRead();
    expect(required.length).toBeGreaterThan(0);
    expect(new Set(required)).toEqual(new Set(["sessionID", "id", "callID", "tool.callID", "metadata.command"]));

    for (const shape of ["flat", "nested"] as const) {
      const evt = permissionAskedEvent({ sessionId: "ses_1", callId: "call_1" }, "perm_1", "echo hi", shape);
      const paths = flattenPaths(evt);
      // Only the callID field that this shape actually carries is expected;
      // the adapter's `props.callID || props.tool?.callID` covers the other.
      const expectedForShape = required.filter((f) => (shape === "flat" ? f !== "tool.callID" : f !== "callID"));
      for (const field of expectedForShape) {
        expect(coversField(paths, field)).toBe(true);
      }
    }
  });

  it("beforeHookOutput with no cwd omits workdir, matching a bash call with no explicit working directory", () => {
    const output = beforeHookOutput("echo hi");
    expect(flattenPaths(output)).toEqual(["args.command"]);
  });

  it("the adapter's own fallback and write-only fields are excluded on purpose, not by omission", () => {
    // A regression here (these fields disappearing from the raw extraction)
    // would mean opencode.ts no longer reads them at all -- worth knowing,
    // since bench/payload.ts's exclusion comment would then be describing
    // code that no longer exists.
    const src = readAdapterSource();
    expect(src).toContain("input?.parameters?.command");
    expect(src).toContain("output.args.description");
  });
});
