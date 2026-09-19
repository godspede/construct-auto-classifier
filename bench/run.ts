/**
 * Certification battery: drives bench/battery.jsonl through the REAL gate --
 * `loadConfig()`, the real classifier `createClassifier()` picks, a real `AutoClassifier`, and opencode's
 * own plugin (`createOpenCodePlugin`) called through its two hooks in
 * opencode's own order -- rather than the LLM client alone. The payloads are
 * built by bench/payload.ts, the one definition tests/battery-fidelity.
 * test.ts checks against the adapter's own source.
 *
 * A prompt or fast-rule change that scores lower than what it replaces does
 * not ship. Because it drives the whole gate rather than the model alone, it
 * also catches a regression a model-only bench structurally could not see: a case that should
 * reach the model getting short-circuited by a fast rule, a landed-script
 * trust, or the sliding-window cache -- which is why every case's actual
 * deciding `source` is scored, not only its verdict.
 *
 *   bun bench/run.ts [--battery FILE] [--model M] [--max-tokens N] [--extra-body JSON] [--prompt-file F] [--only CATEGORY] [--json] [--n-runs N]
 *
 * Deliberately not under tests/: every case that reaches the model is a real
 * LLM call. This is a bench run by hand, never part of `bun test`.
 */
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadConfig } from "../src/config.js";
import { AutoClassifier, createClassifier } from "../src/index.js";
import { StateManager } from "../src/state/state-manager.js";
import { createOpenCodePlugin } from "../src/adapters/opencode.js";
import type { TelemetryRow } from "../src/telemetry.js";
import { gitFixture } from "../tests/helpers/git-fixture.js";
import { beforeHookInput, beforeHookOutput, permissionAskedEvent } from "./payload.js";

type Verdict = "allow" | "deny" | "ask";

interface FixtureSpec {
  /** Repo-relative path the case's `command` invokes. */
  script: string;
  /** Content committed to the fixture repo's remote default branch. */
  content: string;
  /** `landed`: working copy == content. `modified`: working copy is `workContent`, tracked, differs from the remote. `untracked`: `content` is written at `script` but never committed at all. */
  state: "landed" | "modified" | "untracked";
  workContent?: string;
}

interface Case {
  id: string;
  category: string;
  expect: Verdict;
  command: string;
  cwd?: string;
  /** Which stage the case is expected to be decided by; scored separately from `expect`. */
  expect_source?: string;
  /** Whether the deterministic injection tell (rules/injection-detection.ts) is expected to fire; scored separately from `expect`, and never affects it. */
  expect_injection_attempt?: boolean;
  /** Shares a StateManager session with other cases carrying the same value; defaults to the case's own id. Lets an escalation pair run as two ordinary rows. */
  session?: string;
  fixture?: FixtureSpec;
}

interface CaseResult {
  id: string;
  category: string;
  expect: Verdict;
  got: Verdict;
  expectOk: boolean;
  source: string;
  expectSource?: string;
  sourceOk: boolean | null;
  injectionAttempt: boolean;
  expectInjectionAttempt?: boolean;
  injectionOk: boolean | null;
  reason: string;
  ms: number;
  /** Tokens the model calls for this case spent; null when no model was asked. */
  usage: { input_tokens: number; output_tokens: number; calls: number } | null;
  /** Jev's raw answers (Jev runs only), so thresholds can be re-scored offline. */
  jev?: { model?: string; answers: Record<string, unknown> } | null;
}

// ---- CLI -------------------------------------------------------------
const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i !== -1 ? args[i + 1] : undefined;
};
const asJson = args.includes("--json");
const only = flag("--only");
const nRuns = Math.max(1, parseInt(flag("--n-runs") ?? "1", 10) || 1);

if (flag("--prompt-file")) {
  process.env.AUTO_CLASSIFIER_SYSTEM_PROMPT_FILE = path.resolve(flag("--prompt-file")!);
}

// Hermetic: the shipped defaults, never this machine's own config. The
// box-local overlay is skipped, so a box whose gate runs a different model can
// still certify the defaults.
const baseConfig = loadConfig(path.join(import.meta.dir, "bench-config.jsonc"), { overlay: false });
if (flag("--max-tokens")) baseConfig.llm.maxTokens = parseInt(flag("--max-tokens")!, 10);
// Fields merged into every model request, over the route's defaults (a null
// removes one): the knob a model needs when the route default doesn't suit it,
// such as a reasoning model that cannot switch reasoning off.
if (flag("--extra-body")) baseConfig.llm.extraBody = JSON.parse(flag("--extra-body")!);
// --model names what is measured: a Jev version (jev-…) asks Jev, anything else a chat model.
if (flag("--model")) {
  const m = flag("--model")!;
  if (/^jev-/.test(m)) { baseConfig.llm.provider = "jev"; baseConfig.jev.model = m; }
  else { baseConfig.llm.provider = "openai"; baseConfig.llm.model = m; }
}
const measuredModel = baseConfig.llm.provider === "jev" ? `typesafe/${baseConfig.jev.model}` : baseConfig.llm.model;
// One run measures exactly one model; a silent failover must never be
// mistaken for a pass.
baseConfig.llm.fallbackModel = undefined;
baseConfig.llm.triageModel = undefined;

const batteryPath = flag("--battery") ? path.resolve(flag("--battery")!) : path.join(import.meta.dir, "battery.jsonl");
const batteryText = fs.readFileSync(batteryPath, "utf-8");
const allCases: Case[] = batteryText
  .split("\n")
  .filter(Boolean)
  .map((l) => JSON.parse(l) as Case)
  .filter((c) => !only || c.category === only);

if (allCases.length === 0) {
  console.error(`no cases matched${only ? ` --only ${only}` : ""}`);
  process.exit(1);
}

// ---- fixtures ----------------------------------------------------------
function materializeFixture(f: FixtureSpec): string {
  if (f.state === "untracked") {
    const fx = gitFixture();
    const abs = path.join(fx.work, f.script);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, f.content, { mode: 0o755 });
    return fx.work;
  }
  const fx = gitFixture(f.script, f.content);
  if (f.state === "modified") {
    fs.writeFileSync(fx.abs, f.workContent ?? f.content, { mode: 0o755 });
  }
  return fx.work;
}

// ---- one pass over the battery ------------------------------------------
async function runOnce(): Promise<CaseResult[]> {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-classifier-battery-state-"));
  const telemetryPath = path.join(stateDir, "telemetry.jsonl");
  // A fresh state dir per run, so the sliding-window denial/allow cache never
  // leaks across runs; distinct sessions (see `session` above) keep cases
  // within one run from leaking into each other.
  const runConfig = { ...baseConfig, telemetry: { enabled: true, path: telemetryPath } };
  const state = new StateManager(runConfig.policy.slidingWindowMs, runConfig.policy.consecutiveThreshold, stateDir);
  const llm = createClassifier(runConfig);
  const classifier = new AutoClassifier(runConfig, { classifier: llm, stateManager: state });

  const replies: Array<{ permissionId: string; response: string }> = [];
  const ctx = {
    client: {
      postSessionIdPermissionsPermissionId: async (req: { path: { permissionID: string }; body: { response: string } }) => {
        replies.push({ permissionId: req.path.permissionID, response: req.body.response });
      },
    },
  };
  const hooks = createOpenCodePlugin(classifier, { pluginsDir: fs.mkdtempSync(path.join(os.tmpdir(), "auto-classifier-battery-plugins-")) })(ctx);

  const results: CaseResult[] = [];
  for (const c of allCases) {
    const identity = { sessionId: c.session ?? `battery-${c.id}`, callId: `battery-${c.id}` };
    const cwd = c.fixture ? path.join(materializeFixture(c.fixture), c.cwd ?? "") : c.cwd;

    const t0 = Date.now();
    let threw: Error | undefined;
    try {
      // The exact hook opencode calls before a bash tool runs.
      await hooks["tool.execute.before"](beforeHookInput(identity), beforeHookOutput(c.command, cwd));
    } catch (e) {
      threw = e as Error;
    }

    let got: Verdict;
    let reason = threw?.message ?? "";
    if (threw) {
      // A throw from tool.execute.before fails the tool call outright; real
      // opencode never reaches the permission prompt for it, so neither do we.
      got = "deny";
    } else {
      const permissionId = `perm-${c.id}`;
      await hooks.event(permissionAskedEvent(identity, permissionId, c.command));
      const reply = replies.find((r) => r.permissionId === permissionId);
      got = !reply ? "ask" : reply.response === "once" ? "allow" : "deny";
    }
    results.push({
      id: c.id,
      category: c.category,
      expect: c.expect,
      got,
      expectOk: got === c.expect,
      source: "",
      expectSource: c.expect_source,
      sourceOk: null,
      injectionAttempt: false,
      expectInjectionAttempt: c.expect_injection_attempt,
      injectionOk: null,
      reason,
      ms: Date.now() - t0,
      usage: null,
    });
  }

  // Back-fill each case's deciding source (and, where the throw path left no
  // reason, the model's own reason) from the telemetry this run wrote --
  // AutoClassifier.evaluate() already tags every decision with it; no
  // separate instrumentation needed.
  const rows: TelemetryRow[] = fs.existsSync(telemetryPath)
    ? fs
        .readFileSync(telemetryPath, "utf-8")
        .split("\n")
        .filter(Boolean)
        .map((l) => JSON.parse(l) as TelemetryRow)
    : [];
  const byId = new Map(rows.map((r) => [r.id, r]));
  for (const r of results) {
    const row = byId.get(`battery-${r.id}`);
    if (!row) continue;
    r.source = row.source;
    r.usage = row.usage ?? null;
    if (row.jev) r.jev = row.jev;
    if (!r.reason) r.reason = row.reason;
    r.sourceOk = r.expectSource ? row.source === r.expectSource : null;
    r.injectionAttempt = row.injection_attempt;
    r.injectionOk = r.expectInjectionAttempt === undefined ? null : row.injection_attempt === r.expectInjectionAttempt;
  }

  fs.rmSync(stateDir, { recursive: true, force: true });
  return results;
}

// ---- run + aggregate -----------------------------------------------------
const allResults: CaseResult[][] = [];
for (let i = 0; i < nRuns; i++) {
  allResults.push(await runOnce());
}
const flat = allResults.flat();

const total = flat.length;
const correct = flat.filter((r) => r.expectOk).length;
const falseAllows = flat.filter((r) => !r.expectOk && r.got === "allow").length;
const sourceChecked = flat.filter((r) => r.sourceOk !== null);
const sourceCorrect = sourceChecked.filter((r) => r.sourceOk).length;
const injectionChecked = flat.filter((r) => r.injectionOk !== null);
const injectionCorrect = injectionChecked.filter((r) => r.injectionOk).length;
const modelCalls = flat.reduce((n, r) => n + (r.usage?.calls ?? 0), 0);
const inputTokens = flat.reduce((n, r) => n + (r.usage?.input_tokens ?? 0), 0);
const outputTokens = flat.reduce((n, r) => n + (r.usage?.output_tokens ?? 0), 0);
const median = [...flat.map((r) => r.ms)].sort((a, b) => a - b)[Math.floor(total / 2)] ?? 0;

const byCategory = new Map<string, { ok: number; n: number }>();
for (const r of flat) {
  const e = byCategory.get(r.category) ?? { ok: 0, n: 0 };
  e.n++;
  if (r.expectOk) e.ok++;
  byCategory.set(r.category, e);
}

const bySourceStage = new Map<string, number>();
for (const r of flat) {
  bySourceStage.set(r.source || "(none)", (bySourceStage.get(r.source || "(none)") ?? 0) + 1);
}

// Enough provenance for a reader to rerun exactly this measurement.
function gitHead(): string {
  try {
    const sha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: import.meta.dir, encoding: "utf-8" }).trim();
    const dirty = execFileSync("git", ["status", "--porcelain", "--", "src", "bench"], { cwd: import.meta.dir, encoding: "utf-8" }).trim();
    return dirty ? `${sha}+dirty` : sha;
  } catch {
    return "unknown";
  }
}
const provenance = {
  date: new Date().toISOString(),
  commit: gitHead(),
  battery: path.relative(path.join(import.meta.dir, ".."), batteryPath),
  batterySha256: crypto.createHash("sha256").update(batteryText).digest("hex"),
  cases: allCases.length,
  maxTokens: baseConfig.llm.maxTokens,
  extraBody: baseConfig.llm.extraBody ?? null,
  bun: Bun.version,
};

if (asJson) {
  console.log(
    JSON.stringify(
      {
        ...provenance,
        model: measuredModel,
        runs: nRuns,
        total,
        correct,
        falseAllows,
        medianMs: median,
        modelCalls,
        inputTokens,
        outputTokens,
        sourceChecked: sourceChecked.length,
        sourceCorrect,
        injectionChecked: injectionChecked.length,
        injectionCorrect,
        byCategory: Object.fromEntries(byCategory),
        bySourceStage: Object.fromEntries(bySourceStage),
        results: flat,
      },
      null,
      2
    )
  );
} else {
  console.log(`model: ${measuredModel}  runs: ${nRuns}`);
  console.log(`overall: ${correct}/${total} (${((100 * correct) / total).toFixed(1)}%)  false-allows: ${falseAllows}  median: ${median}ms`);
  console.log(`tokens:  ${inputTokens} in / ${outputTokens} out across ${modelCalls} model calls`);
  console.log(`source:  ${sourceCorrect}/${sourceChecked.length} of the ${sourceChecked.length} cases with an expect_source matched it`);
  console.log(`injection: ${injectionCorrect}/${injectionChecked.length} of the ${injectionChecked.length} cases with an expect_injection_attempt matched it`);
  console.log("\nby category:");
  for (const [cat, e] of byCategory) console.log(`  ${cat.padEnd(22)} ${e.ok}/${e.n}`);
  console.log("\nby deciding stage:");
  for (const [src, n] of bySourceStage) console.log(`  ${src.padEnd(22)} ${n}`);

  const misses = flat.filter((r) => !r.expectOk);
  if (misses.length) {
    console.log("\nmisses (verdict):");
    for (const r of misses) {
      console.log(`  [${r.id}] expected ${r.expect}, got ${r.got} (source: ${r.source}): ${r.reason.slice(0, 140)}`);
    }
  }

  const sourceMisses = flat.filter((r) => r.sourceOk === false);
  if (sourceMisses.length) {
    console.log("\nsource mismatches (verdict may still be right -- this is the short-circuit regression the battery exists to catch):");
    for (const r of sourceMisses) {
      console.log(`  [${r.id}] expected source ${r.expectSource}, got ${r.source} (verdict: ${r.got})`);
    }
  }

  const injectionMisses = flat.filter((r) => r.injectionOk === false);
  if (injectionMisses.length) {
    console.log("\ninjection-attempt mismatches (verdict may still be right -- this is telemetry only):");
    for (const r of injectionMisses) {
      console.log(`  [${r.id}] expected injection_attempt ${r.expectInjectionAttempt}, got ${r.injectionAttempt}`);
    }
  }
}
