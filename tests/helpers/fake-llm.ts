import type { ClassificationResult } from "../../src/types.js";
import type { Classifier } from "../../src/classifier/client.js";

export type FakeVerdict = { allow: boolean; reason?: string } | Error;

/**
 * A scripted stand-in for LlmClient. Each call pops the next verdict; a verdict
 * that is an Error is thrown, which is how the real client surfaces a dead
 * endpoint. Records every call so a test can assert the LLM was (not) consulted.
 */
export class FakeLlm implements Classifier {
  calls: Array<{ command: string; fileContext?: unknown }> = [];
  private queue: FakeVerdict[];
  private fallback: FakeVerdict;

  constructor(verdicts: FakeVerdict[] = [], fallback: FakeVerdict = { allow: false, reason: "fake default deny" }) {
    this.queue = [...verdicts];
    this.fallback = fallback;
  }

  async classify(command: string, fileContext?: unknown): Promise<ClassificationResult> {
    this.calls.push({ command, fileContext });
    const next = this.queue.length > 0 ? this.queue.shift()! : this.fallback;
    if (next instanceof Error) {
      return { allow: false, reason: `LLM classification unreachable: ${next.message}`, source: "error" };
    }
    return { allow: next.allow, reason: next.reason ?? (next.allow ? "fake allow" : "fake deny"), source: "llm" };
  }
}
