import { describe, it, expect } from "bun:test";
import { analyzeCommand, unmodelledConstructs, MAX_ANALYSED_LENGTH } from "../src/rules/command-shape.js";
import { evaluateFastRules } from "../src/rules/fast-rules.js";
import { findScriptInvocation } from "../src/context/script-provenance.js";
import { AutoClassifier } from "../src/index.js";
import { StateManager } from "../src/state/state-manager.js";
import type { RulesConfig } from "../src/types.js";
import { FakeLlm } from "./helpers/fake-llm.js";
import { testConfig } from "./helpers/config.js";
import { tmpStateDir } from "./helpers/tmp-state.js";
import { gitFixture } from "./helpers/git-fixture.js";

/**
 * The fail-closed backstop. A command line holding syntax the analyser does
 * not fully model -- a comment, grouping, a compound command, an alias,
 * nested or cross-shell quoting, a control or lookalike character, a line too
 * long to trust -- is never allowed without the model: no fast allow, no
 * landed-script trust, no scratch-redirect exemption and no cache hit. It
 * goes to normal evaluation, where the deterministic denials still apply.
 *
 * Every command string in this file is data handed to the gate. None is ever run.
 */

const CONFIG = "~/.config/auto-classifier/config.jsonc";
/** A scratch path that does not exist, so no symlink on this box can disqualify it. */
const SCRATCH = `/tmp/aclass-guard-${process.pid}-${Date.now()}.txt`;

const rules: RulesConfig = {
  fastDeny: ["^\\s*mkfs(\\.[a-z0-9]+)?\\s+"],
  fastAllow: [
    "^\\s*journalctl\\b",
    "^\\s*rg\\b",
    "^\\s*git\\s+(?:-c\\s+[^;&|]+?\\s+)*(?:status|diff|log|show|commit|add)\\b",
    "^\\s*ls\\b",
    "^\\s*pwd$",
    "^\\s*npm\\s+test\\b",
    "^\\s*(?:Get-ChildItem|Get-Content)\\b",
  ],
};

function build(llm: FakeLlm) {
  const config = testConfig({}, rules);
  const state = new StateManager(config.policy.slidingWindowMs, config.policy.consecutiveThreshold, tmpStateDir());
  return new AutoClassifier(config, { classifier: llm, stateManager: state });
}

const flagged = (c: string) => unmodelledConstructs(c).length > 0;
const fast = (c: string) => evaluateFastRules(c, rules)?.matched ?? null;

/**
 * Each entry: [what it covers, a line the guard must flag]. Every line starts
 * with a verb a rule above allows, so the only thing standing between it and
 * a fast allow is the construct itself.
 */
const GUARDED: Array<[string, string]> = [
  // comments
  ["a word-start comment", "rg x # note"],
  ["a comment after an operator", "rg x;# note"],
  ["a `#` mid-word (a comment to some shell)", "rg a#b"],
  ["a PowerShell block comment", "Get-Content x <# note #>"],
  ["a PowerShell block comment inside quotes", "Get-Content 'x <# note #>'"],
  // definitions and state changes
  ["coproc", "rg x; coproc pwd"],
  ["a function keyword", "rg x; function f { pwd; }"],
  ["a name() definition", "rg x; f() { pwd; }"],
  ["alias", "rg x; alias rg=pwd"],
  ["unalias", "rg x; unalias rg"],
  ["alias through builtin", "rg x; builtin alias rg=pwd"],
  ["alias with its name escaped", "rg x; \\alias rg=pwd"],
  ["alias with its name quoted", "rg x; 'alias' rg=pwd"],
  ["shopt", "rg x; shopt -s expand_aliases"],
  ["set", "rg x; set -k"],
  ["hash", "rg x; hash -p /tmp/x rg"],
  ["enable", "rg x; enable -n rg"],
  ["trap", "rg x; trap pwd DEBUG"],
  // compound commands
  ["case/esac", "rg x; case a in a) pwd;; esac"],
  ["select", "rg x; select a in b; do pwd; done"],
  ["[[ ]]", "rg x; [[ -f a ]]"],
  ["if", "rg x; if pwd; then pwd; fi"],
  ["for", "rg x; for a in b; do pwd; done"],
  ["while", "rg x; while pwd; do pwd; done"],
  ["!", "rg x; ! pwd"],
  ["time -p", "rg x; time -p pwd"],
  // grouping
  ["a subshell", "rg x; (pwd)"],
  ["a subshell glued to its verb", "(rg x)"],
  ["a brace group", "rg x; { pwd; }"],
  ["a lone closing brace", "rg x }"],
  ["arithmetic", "rg $((1+2))"],
  ["an arithmetic command", "rg x; ((a=1))"],
  ["an extended glob", "ls !(x)"],
  ["an array assignment", "a=(1 2) rg x"],
  // substitution
  ["process substitution (input)", "rg x <(pwd)"],
  ["process substitution (output)", "rg x >(pwd)"],
  ["command substitution", "rg $(pwd)"],
  ["backticks", "rg `pwd`"],
  ["backticks inside double quotes", 'rg "`pwd`"'],
  // quoting
  ['$"..."', 'rg $"x"'],
  ["nested quotes in a parameter expansion", "rg ${x/'a'/b}"],
  ["nested double quotes in a parameter expansion", 'rg "${x#"a"}"'],
  ["an unterminated quote", "rg 'x"],
  ["an escaped quote in double quotes (not an escape to PowerShell or cmd)", 'rg "a\\"b"'],
  ["an escaped quote in ANSI-C quotes", "rg $'a\\'b'"],
  ["an escaped separator (a separator to PowerShell)", "rg x \\; pwd"],
  ["an escaped pipe", "rg x \\| pwd"],
  ["a line continuation (a line break to PowerShell)", "rg x \\\npwd"],
  ["cmd's escaped quote", 'rg a ^"b"'],
  ["a PowerShell here-string", "Get-Content @'\nx\n'@"],
  ["a curly double quote", "rg \u201cx\u201d"],
  ["a curly apostrophe inside ASCII quotes", 'rg "it\u2019s"'],
  // characters
  ["NUL", "rg x\u0000pwd"],
  ["a bell", "rg x\u0007"],
  ["an escape sequence", "rg \u001b[31mx"],
  ["DEL", "rg x\u007f"],
  ["a C1 control (NEL)", "rg x\u0085pwd"],
  ["a lone carriage return (a line break to PowerShell and cmd)", "rg x\rpwd"],
  ["a zero-width space inside quotes", 'rg "a\u200bb"'],
  ["a right-to-left override inside quotes", 'rg "a\u202eb"'],
  ["a Unicode line separator inside quotes", 'rg "a\u2028b"'],
  ["a fullwidth semicolon outside quotes", "rg x \uff1b pwd"],
  ["a Greek question mark (a `;` lookalike) outside quotes", "rg x \u037e pwd"],
  ["a fullwidth solidus outside quotes", "ls \uff0fetc"],
  ["a non-breaking space outside quotes", "rg x\u00a0pwd"],
  // here-documents
  ["<<-", "rg x <<-EOF\n\tbody\n\tEOF"],
  ["<<", "rg x <<EOF\nbody\nEOF"],
  // length
  ["a line over the length cap", "rg " + "a".repeat(MAX_ANALYSED_LENGTH)],
];

/** Lines the analyser fully models: the guard must leave them alone. */
const MODELLED: string[] = [
  "git status",
  "ls -la /tmp",
  "rg -n foo src/",
  "journalctl -u nginx --since today",
  'git commit -m "fix: the thing"',
  "git commit -m 'it''s fine'",
  'git commit -m "caf\u00e9 cr\u00e8me"',
  "rg 'a#b'",
  'rg "a # b"',
  "rg a\\#b",
  "ls 2>&1",
  "ls > /dev/null",
  "rg x <<<word",
  "rg $'a\\nb'",
  "rg ${HOME}",
  "rg $HOME",
  "ls\r\npwd",
  "ls\t-la",
  "ls\npwd",
  "time ls",
  "find . -name '*.ts' -exec cat {} +",
  "rg 'x' | head -5",
  "git log --format='%H {x}'",
  "rg " + "a".repeat(MAX_ANALYSED_LENGTH - 3),
];

describe("unmodelledConstructs flags every construct the analyser does not model", () => {
  for (const [what, c] of GUARDED) {
    it(`flags ${what}`, () => {
      expect(flagged(c)).toBe(true);
    });
  }
});

describe("unmodelledConstructs leaves fully modelled lines alone", () => {
  for (const c of MODELLED) {
    it(`does not flag ${JSON.stringify(c).slice(0, 60)}`, () => {
      expect(unmodelledConstructs(c)).toEqual([]);
    });
  }
});

describe("fast allow never vouches for a guarded line", () => {
  for (const [what, c] of GUARDED) {
    it(`${what}`, () => {
      expect(fast(c)).not.toBe("allow");
    });
  }

  it("the guard's reasons are tells", () => {
    const shape = analyzeCommand("rg x # note");
    expect(shape.unmodelled.length).toBeGreaterThan(0);
    for (const r of shape.unmodelled) expect(shape.tells).toContain(r);
  });

  it("a scratch redirect on a guarded line is no exemption", () => {
    expect(fast(`journalctl > ${SCRATCH}`)).toBe("allow");
    expect(fast(`journalctl > ${SCRATCH} # note`)).toBeNull();
    expect(fast(`journalctl > ${SCRATCH}; (pwd)`)).toBeNull();
  });

  it("controls: the same verbs without the construct are fast-allowed", () => {
    for (const c of ["rg x", "rg x; pwd", "ls /etc", "Get-Content x", "journalctl -u x", "rg x\npwd"]) {
      expect(fast(c)).toBe("allow");
    }
  });
});

describe("the whole gate: a guarded line is never allowed without the model", () => {
  for (const [what, c] of GUARDED) {
    it(`${what}`, async () => {
      const llm = new FakeLlm([], { allow: true, reason: "stub allow" });
      const out = await build(llm).evaluate(c, "s");
      // Either the model was asked, or a deterministic stop denied it.
      if (out.decision === "allow") expect(llm.calls.length).toBe(1);
      else expect(out.decision).toBe("deny");
    });
  }

  it("no cache hit: the same guarded line is asked again", async () => {
    const llm = new FakeLlm([], { allow: true, reason: "stub allow" });
    const gate = build(llm);
    await gate.evaluate("make build # again", "s");
    const second = await gate.evaluate("make build # again", "s");
    expect(llm.calls.length).toBe(2);
    expect(second.reason).not.toContain("same verdict");
  });

  it("control: an unguarded line the model allowed is a cache hit the second time", async () => {
    const llm = new FakeLlm([], { allow: true, reason: "stub allow" });
    const gate = build(llm);
    await gate.evaluate("make build", "s");
    const second = await gate.evaluate("make build", "s");
    expect(llm.calls.length).toBe(1);
    expect(second.reason).toContain("same verdict");
  });

  it("a denied guarded line is still counted, and escalates on retry", async () => {
    const llm = new FakeLlm([], { allow: false, reason: "stub deny" });
    const gate = build(llm);
    const first = await gate.evaluate("make build # x", "s");
    expect(first.decision).toBe("deny");
    await gate.evaluate("make build # x", "s");
    const third = await gate.evaluate("make build # x", "s");
    expect(third.escalated).toBe(true);
  });
});

describe("deterministic denials still apply to a guarded line", () => {
  for (const c of [
    `rm ${CONFIG} # note`,
    `echo x > ${CONFIG} # it's`,
    `{ rm ${CONFIG}; }`,
    `(rm ${CONFIG})`,
    `(rm -f ${CONFIG}; pwd)`,
    `! rm ${CONFIG}`,
    `if true; then rm ${CONFIG}; fi`,
    `for a in b; do rm ${CONFIG}; done`,
    `while false; do rm ${CONFIG}; done`,
    `coproc rm ${CONFIG}`,
    `time -p rm ${CONFIG}`,
    `rg x; (AUTO_CLASSIFIER_DENY_MODE=auto-retry pwd)`,
  ]) {
    it(`${JSON.stringify(c)} is refused by self-protection, no model`, async () => {
      const llm = new FakeLlm([], { allow: true, reason: "stub allow" });
      const out = await build(llm).evaluate(c, "s");
      expect(out.decision).toBe("deny");
      expect(out.reason).toContain("self-protection");
      expect(llm.calls.length).toBe(0);
    });
  }

  it("a fastDeny pattern inside a subshell is refused, no model", async () => {
    const llm = new FakeLlm([], { allow: true, reason: "stub allow" });
    const out = await build(llm).evaluate("(mkfs.ext4 /dev/sda)", "s");
    expect(out.decision).toBe("deny");
    expect(llm.calls.length).toBe(0);
  });
});

describe("landed-script trust never covers a guarded line", () => {
  it("control: the narrow shape is trusted", async () => {
    const f = gitFixture();
    const llm = new FakeLlm();
    const out = await build(llm).evaluate("./deploy/publish.sh --dry-run", "s", undefined, { cwd: f.work });
    expect(out.reason).toContain("Landed script");
    expect(llm.calls.length).toBe(0);
  });

  for (const [what, c] of [
    ["an argument past the length cap", "./deploy/publish.sh " + "a".repeat(MAX_ANALYSED_LENGTH)],
    ["a trailing comment", "./deploy/publish.sh # note"],
    ["a subshell", "(./deploy/publish.sh)"],
  ] as const) {
    it(`${what} goes to the model`, async () => {
      const f = gitFixture();
      const llm = new FakeLlm([], { allow: true, reason: "stub allow" });
      const out = await build(llm).evaluate(c, "s", undefined, { cwd: f.work });
      expect(out.reason).not.toContain("Landed script");
      expect(llm.calls.length).toBe(1);
    });
  }

  it("findScriptInvocation: a guarded line is never plain", () => {
    expect(findScriptInvocation("./deploy/publish.sh " + "a".repeat(MAX_ANALYSED_LENGTH))?.plain).toBe(false);
  });
});
