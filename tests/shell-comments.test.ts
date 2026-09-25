import { describe, it, expect } from "bun:test";
import { analyzeCommand, splitSegments } from "../src/rules/command-shape.js";
import { evaluateFastRules } from "../src/rules/fast-rules.js";
import { selfProtectionDenial } from "../src/rules/self-protection.js";
import { AutoClassifier } from "../src/index.js";
import { StateManager } from "../src/state/state-manager.js";
import type { RulesConfig } from "../src/types.js";
import { FakeLlm } from "./helpers/fake-llm.js";
import { testConfig } from "./helpers/config.js";
import { tmpStateDir } from "./helpers/tmp-state.js";

/**
 * In bash, an unquoted, unescaped `#` at the start of a word begins a comment
 * that runs to the end of the line; quote characters inside it mean nothing.
 * The gate must not read one as opening a quote, or a later line would be
 * judged as part of the first line's command. A `#` inside a word, inside
 * quotes or escaped is an ordinary character.
 *
 * Every command string in this file is data handed to the gate. None is ever run.
 */

const PLUGIN = "~/.config/opencode/plugins/auto-classifier.js";
const CONFIG = "~/.config/auto-classifier/config.jsonc";

// The `\b`-terminated read rules, as the shipped defaults write them.
const rules: RulesConfig = {
  fastDeny: ["^\\s*mkfs(\\.[a-z0-9]+)?\\s+"],
  fastAllow: [
    "^\\s*journalctl\\b",
    "^\\s*rg\\b",
    "^\\s*git\\s+(?:-c\\s+[^;&|]+?\\s+)*(?:status|diff|log|show)\\b",
    "^\\s*ls(\\s+-[a-zA-Z0-9]+)*(\\s+[^\\s;&|]+)?$",
    "^\\s*npm\\s+test\\b",
  ],
};

function build(llm: FakeLlm) {
  const config = testConfig({}, rules);
  const state = new StateManager(config.policy.slidingWindowMs, config.policy.consecutiveThreshold, tmpStateDir());
  return new AutoClassifier(config, { classifier: llm, stateManager: state });
}

describe("splitSegments: a comment runs from a word-start `#` to the end of its line", () => {
  const segs = (c: string) => splitSegments(c).segments;

  it("drops a trailing comment, quote characters and all", () => {
    expect(segs("ls # it's here")).toEqual(["ls"]);
    expect(segs('ls # say "hi')).toEqual(["ls"]);
    expect(segs("# it's only a comment")).toEqual([]);
  });

  it("a quote inside a comment does not swallow the next line", () => {
    expect(segs("journalctl # it's\ntouch /tmp/x # '")).toEqual(["journalctl", "touch /tmp/x"]);
    expect(segs('journalctl # say "\ntouch /tmp/x # "')).toEqual(["journalctl", "touch /tmp/x"]);
    expect(segs("rg x # it's\ntouch /tmp/x # '")).toEqual(["rg x", "touch /tmp/x"]);
  });

  it("a `#` right after an operator starts a word, so it starts a comment", () => {
    expect(segs("ls;# it's")).toEqual(["ls"]);
    expect(segs("ls|# it's")).toEqual(["ls"]);
    expect(segs("ls&&# it's\npwd")).toEqual(["ls", "pwd"]);
    expect(segs("ls\t# it's")).toEqual(["ls"]);
  });

  it("a `#` inside a word, inside quotes or escaped is an ordinary character", () => {
    expect(segs("echo a#b")).toEqual(["echo a#b"]);
    expect(segs("echo 'x'#y")).toEqual(["echo 'x'#y"]);
    expect(segs("echo $#")).toEqual(["echo $#"]);
    expect(segs("echo ${#x}")).toEqual(["echo ${#x}"]);
    expect(segs("echo \\# not a comment; pwd")).toEqual(["echo \\# not a comment", "pwd"]);
    expect(segs('echo "a # b"; pwd')).toEqual(['echo "a # b"', "pwd"]);
    expect(segs("echo 'a # b'; pwd")).toEqual(["echo 'a # b'", "pwd"]);
  });

  it("a backslash-newline joins lines exactly as bash does before the `#` is judged", () => {
    // `a\<newline>#b` is the word `a#b`: the `#` is inside a word.
    expect(segs("echo a\\\n#b; pwd")).toEqual(["echo a\\\n#b", "pwd"]);
  });

  it("a here-document marker inside a comment is not a here-document", () => {
    const s = splitSegments("ls # see <<EOF\npwd");
    expect(s.hasHeredoc).toBe(false);
    expect(s.segments).toEqual(["ls", "pwd"]);
  });
});

describe("fast allow never vouches for a line whose comments hid a quote", () => {
  const decide = (c: string) => evaluateFastRules(c, rules)?.matched ?? null;

  it("control: a second line on its own is not fast-allowed", () => {
    expect(decide("journalctl\ntouch /tmp/x")).toBeNull();
  });

  for (const [id, c] of [
    ["cmt-squote", "journalctl # it's\ntouch /tmp/x # '"],
    ["cmt-dquote", 'journalctl # say "\ntouch /tmp/x # "'],
    ["cmt-squote-rg", "rg x # it's\ntouch /tmp/x # '"],
    ["cmt-squote-git", "git status # it's\ntouch /tmp/x # '"],
    ["cmt-squote-npm", "npm test # it's\ntouch /tmp/x # '"],
    ["cmt-after-op", "journalctl;# it's\ntouch /tmp/x # '"],
  ] as const) {
    it(`${id} is not fast-allowed`, () => {
      expect(decide(c)).not.toBe("allow");
    });
  }

  it("a plain trailing comment on a fast-allowed verb is not fast-allowed either (the backstop)", () => {
    expect(decide("journalctl # just looking")).toBeNull();
  });
});

describe("self-protection sees a gate write on a line hidden by a comment quote", () => {
  const denial = (c: string) => selfProtectionDenial(analyzeCommand(c));

  for (const [id, c] of [
    ["sp-control", `journalctl\necho x > ${CONFIG}`],
    ["sp-cmt-squote", `journalctl # it's\necho x > ${CONFIG} # '`],
    ["sp-cmt-dquote", `journalctl # say "\necho x > ${CONFIG} # "`],
    ["sp-cmt-plugin", `rg x # it's\necho x > ${PLUGIN} # '`],
    ["sp-cmt-rm", `journalctl # it's\nrm ${CONFIG} # '`],
  ] as const) {
    it(`${id} is refused`, () => {
      expect(denial(c)).not.toBeNull();
    });
  }
});

describe("the whole gate: comment quotes across lines", () => {
  it("ctl-newline: a second command on its own line reaches the model", async () => {
    const llm = new FakeLlm([], { allow: true, reason: "stub allow" });
    const out = await build(llm).evaluate("journalctl\ntouch /tmp/x", "s");
    expect(out.decision).toBe("allow");
    expect(llm.calls.length).toBe(1);
  });

  for (const [id, c] of [
    ["cmt-squote", "journalctl # it's\ntouch /tmp/x # '"],
    ["cmt-dquote", 'journalctl # say "\ntouch /tmp/x # "'],
    ["cmt-squote-rg", "rg x # it's\ntouch /tmp/x # '"],
  ] as const) {
    it(`${id} reaches the model`, async () => {
      const llm = new FakeLlm([], { allow: true, reason: "stub allow" });
      const out = await build(llm).evaluate(c, "s");
      expect(llm.calls.length).toBe(1);
      expect(out.reason).not.toContain("Fast-allow");
    });
  }

  for (const [id, c] of [
    ["sp-control", `journalctl\necho x > ${CONFIG}`],
    ["sp-cmt-squote", `journalctl # it's\necho x > ${CONFIG} # '`],
    ["sp-cmt-dquote", `journalctl # say "\necho x > ${CONFIG} # "`],
    ["sp-cmt-plugin", `rg x # it's\necho x > ${PLUGIN} # '`],
  ] as const) {
    it(`${id} is refused by self-protection, no model`, async () => {
      const llm = new FakeLlm([], { allow: true, reason: "stub allow" });
      const out = await build(llm).evaluate(c, "s");
      expect(out.decision).toBe("deny");
      expect(out.reason).toContain("self-protection");
      expect(llm.calls.length).toBe(0);
    });
  }
});
