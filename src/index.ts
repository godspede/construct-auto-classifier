import { loadConfig } from "./config.js";
import { evaluateFastRules } from "./rules/fast-rules.js";
import { LlmClient, type Classifier } from "./classifier/client.js";
import { JevClient } from "./classifier/jev-client.js";
import { StateManager } from "./state/state-manager.js";
import { scriptProvenance, type GitRunner } from "./context/script-provenance.js";
import { writeTelemetry, snippetOf } from "./telemetry.js";
import { detectInjectionAttempt } from "./rules/injection-detection.js";
import { VERSION } from "./version.js";
import crypto from "node:crypto";
import type { AppConfig, DecisionOutcome, ClassificationResult, FileContext } from "./types.js";

export * from "./types.js";
export { loadConfig } from "./config.js";
export { LlmClient, type Classifier } from "./classifier/client.js";
export { JevClient } from "./classifier/jev-client.js";

/** `llm.provider: "jev"` asks Jev; anything else asks the chat model over the OpenAI-compatible client. */
export function createClassifier(config: AppConfig): Classifier {
  return config.llm.provider === "jev"
    ? new JevClient(config.jev, undefined, config.llm.maxFileChars)
    : new LlmClient(config.llm);
}
export { StateManager } from "./state/state-manager.js";
export { scriptProvenance, findScriptInvocation } from "./context/script-provenance.js";
export { VERSION } from "./version.js";
export { log } from "./log.js";

/** Seams a caller may replace: the LLM (tests script it) and where state lives. */
export interface AutoClassifierDeps {
  classifier?: Classifier;
  stateManager?: StateManager;
  /** How git is run for script provenance; tests may script it. */
  git?: GitRunner;
}

export interface EvaluateOptions {
  /** Directory the command will run in; relative script paths resolve against it. */
  cwd?: string;
  /** The harness's own id for this tool call, for the telemetry row. */
  callId?: string;
}

/** A decision plus which stage made it, for telemetry. */
interface Decided {
  outcome: DecisionOutcome;
  source: string;
  usage?: ClassificationResult["usage"];
  jev?: ClassificationResult["jev"];
  fileContext?: FileContext;
}

export class AutoClassifier {
  private config: AppConfig;
  private llmClient: Classifier;
  private stateManager: StateManager;
  private git?: GitRunner;

  constructor(config?: AppConfig, deps: AutoClassifierDeps = {}) {
    this.config = config || loadConfig();
    this.llmClient = deps.classifier ?? createClassifier(this.config);
    this.stateManager =
      deps.stateManager ??
      new StateManager(this.config.policy.slidingWindowMs, this.config.policy.consecutiveThreshold);
    this.git = deps.git;
  }

  getConfig(): AppConfig {
    return this.config;
  }

  async evaluate(
    command: string,
    sessionId: string = "default-session",
    fileContext?: FileContext,
    opts: EvaluateOptions = {}
  ): Promise<DecisionOutcome> {
    const started = Date.now();
    const decided = await this.decide(command, sessionId, fileContext, opts);
    if (command.trim()) {
      // A property of what was SHOWN to the gate, not of how it was decided:
      // computed after decide() returns but never fed back into it, so a
      // fast-allow, a cache hit, and a model call are all flagged the same
      // way and none of their verdicts can move because of it.
      const injectionPattern = detectInjectionAttempt(command) ?? detectInjectionAttempt(decided.fileContext?.content ?? "");
      writeTelemetry(this.config.telemetry, {
        id: opts.callId ?? "",
        session: sessionId,
        command: command.trim(),
        file_path: decided.fileContext?.path ?? null,
        file_snippet: snippetOf(decided.fileContext),
        decision: decided.outcome.decision,
        source: decided.source,
        reason: decided.outcome.reason ?? "",
        latency_ms: Date.now() - started,
        model: decided.source === "llm" || decided.source === "fallback" || decided.source === "triage" || decided.source === "error" || decided.source === "truncated" ? (this.config.llm.provider === "jev" ? decided.jev?.model ?? this.config.jev.model ?? null : this.config.llm.model) : null,
        injection_attempt: injectionPattern !== null,
        injection_pattern: injectionPattern,
        cwd: opts.cwd ?? null,
        usage: decided.usage ?? null,
        jev: decided.jev ?? null,
      });
    }
    return decided.outcome;
  }

  private async decide(
    command: string,
    sessionId: string,
    fileContext: FileContext | undefined,
    opts: EvaluateOptions
  ): Promise<Decided> {
    const trimmed = command.trim();
    if (!trimmed) {
      return { outcome: { decision: "allow", reason: "Empty command", consecutiveCount: 0, escalated: false }, source: "empty" };
    }

    // 1. Fast Rules Evaluation
    const fastRule = evaluateFastRules(trimmed, this.config.rules);
    if (fastRule) {
      if (fastRule.matched === "allow") {
        // Fast-allowed means structurally read-only: it must not reset the
        // consecutive-denial counter, or an agent could interleave `ls` between
        // retries forever.
        this.stateManager.recordAllow(sessionId, trimmed, { exploratory: true });
        return {
          outcome: { decision: "allow", reason: `Fast-allow rule matched (${fastRule.pattern})`, consecutiveCount: 0, escalated: false },
          source: "fast-allow",
        };
      } else {
        // Fast deny matched
        return { outcome: this.handleDenial(sessionId, trimmed, `Critical safety rule matched (${fastRule.pattern})`), source: "fast-deny" };
      }
    }

    // 2. A retry of a command this session was already denied inside the
    // window does not go back to the model: the verdict is known, and what the
    // retry is for is the count toward operator review.
    // A denial that was really an unreachable model is counted but never
    // reused: the retry gets a fresh call.
    const prior = this.stateManager.recentDenial(sessionId, trimmed);
    if (prior && !prior.transient) {
      return { outcome: this.handleDenial(sessionId, trimmed, prior.reason), source: "retry" };
    }

    // 3. A script run gets judged on facts about the script, not on its name.
    if (!fileContext) {
      const prov = scriptProvenance(trimmed, opts.cwd ?? process.cwd(), { maxChars: this.config.llm.maxFileChars, git: this.git });
      if (prov) {
        if (prov.landed && this.config.policy.trustLandedScripts) {
          this.stateManager.recordAllow(sessionId, trimmed, { exploratory: false });
          return {
            outcome: { decision: "allow", reason: `Landed script: ${prov.summary}`, consecutiveCount: 0, escalated: false },
            source: "landed",
            fileContext: { path: prov.path, content: "", provenance: prov.summary },
          };
        }
        fileContext = { path: prov.path, content: prov.content ?? "", provenance: prov.summary, truncated: prov.truncated, originalLength: prov.originalLength };
      }
    }

    // 4. The model only sees the text it is shown, so the same text inside the
    // window gets the same answer without asking again.
    const contextKey = fileContext ? crypto.createHash("sha1").update(fileContext.content).digest("hex").slice(0, 16) : undefined;
    const cached = this.stateManager.recentAllow(sessionId, trimmed, contextKey);
    if (cached) {
      return {
        outcome: { decision: "allow", reason: `${cached.reason} (same verdict as earlier in this session)`, consecutiveCount: 0, escalated: false },
        source: "cache",
        fileContext,
      };
    }

    // 5. LLM Classification Evaluation
    const result: ClassificationResult = await this.llmClient.classify(trimmed, fileContext, sessionId);

    if (result.allow && fileContext?.truncated) {
      // The model reasoned about a head-slice as though it were the whole
      // file; its allow says nothing about what it did not see, and must not
      // become a gate allow. This does not depend on the model noticing the
      // truncation marker in the prompt -- it is enforced here regardless.
      // Ask when someone can answer; deny when nobody can, since an
      // unanswerable prompt on a headless box is not a gate.
      const rawReason = `Script content was truncated (showing ${fileContext.content.length} of ${fileContext.originalLength} characters) before the classifier saw it; a partial file cannot be safely allowed. Model said: ${result.reason}`;
      return {
        outcome: {
          decision: this.config.policy.headless ? "deny" : "ask",
          reason: rawReason,
          consecutiveCount: 0,
          escalated: false,
        },
        source: "truncated",
        fileContext,
        usage: result.usage,
        jev: result.jev,
      };
    }

    if (result.allow) {
      this.stateManager.recordAllow(sessionId, trimmed, { exploratory: false, reason: result.reason, contextKey });
      return { outcome: { decision: "allow", reason: result.reason, consecutiveCount: 0, escalated: false }, source: result.source, fileContext, usage: result.usage, jev: result.jev };
    }

    // 6. LLM Denied Command
    return { outcome: this.handleDenial(sessionId, trimmed, result.reason, result.source === "error"), source: result.source, fileContext, usage: result.usage, jev: result.jev };
  }

  private handleDenial(
    sessionId: string,
    command: string,
    rawReason: string,
    transient = false
  ): DecisionOutcome {
    const { consecutiveCount, escalated } = this.stateManager.recordDenial(
      sessionId,
      command,
      rawReason,
      { transient }
    );

    const mode = this.config.policy.denyMode;

    if (mode === "ask-user") {
      return {
        decision: "force_ask",
        reason: `Command flagged for review: ${rawReason}`,
        consecutiveCount,
        escalated: true,
      };
    }

    if (mode === "auto-retry") {
      return {
        decision: "deny",
        reason: this.formatDenialMessage(rawReason, false, consecutiveCount),
        consecutiveCount,
        escalated: false,
      };
    }

    // mode === "both"
    if (escalated && this.config.policy.headless) {
      // Nobody can answer a prompt here, so an escalation is a denial that says
      // so, never a permission left pending (or auto-answered by the harness).
      return {
        decision: "deny",
        reason: [
          `Action blocked by safety classifier, ${consecutiveCount} times: ${rawReason}.`,
          `This session is headless: no operator can answer a prompt here. Stop, and report to the operator that this command needs their decision.`,
        ].join(" "),
        consecutiveCount,
        escalated: true,
      };
    }

    if (escalated) {
      return {
        decision: "force_ask",
        reason: [
          `⚠️ SAFETY ESCALATION: the safety classifier has blocked this command ${consecutiveCount} times.`,
          `Command: ${command}`,
          `Classifier Finding: ${rawReason}`,
          `[!] Note: If the agent provided an explanation above, please verify it carefully before deciding.`,
        ].join("\n"),
        consecutiveCount,
        escalated: true,
      };
    }

    return {
      decision: "deny",
      reason: this.formatDenialMessage(rawReason, true, consecutiveCount),
      consecutiveCount,
      escalated: false,
    };
  }

  private formatDenialMessage(
    rawReason: string,
    instructAgent: boolean,
    consecutiveCount: number
  ): string {
    if (!instructAgent || !this.config.policy.instructAgentOnDenial) {
      return `Action blocked by safety classifier: ${rawReason}. Please find a safer approach.`;
    }

    const remaining = Math.max(
      1,
      this.config.policy.consecutiveThreshold - consecutiveCount
    );
    // The agent is told plainly what happens on the retry that escalates: an
    // operator has to approve it, and with nobody there it stays blocked.
    const next =
      remaining > 1
        ? ` (${remaining} attempt(s) remaining before operator review).`
        : this.config.policy.headless
          ? `. Running this exact command again will be blocked: no operator is present to approve it.`
          : `. Running this exact command again will be held for the operator's approval, and it stays blocked if no operator is there to approve it.`;

    return [
      `Action blocked by safety classifier: ${rawReason}.`,
      `If this command is safe and strictly necessary, output a clear explanation to the user addressing why the classifier's concern does not apply and why this action is safe, then attempt the command again${next}`,
      `Otherwise, find a safer alternative.`,
    ].join(" ");
  }
}
