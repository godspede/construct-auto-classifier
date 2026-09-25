export interface LlmConfig {
  provider?: string;
  baseUrl: string;
  apiKey?: string;
  /**
   * Path to a file whose trimmed contents are the bearer token, read when
   * `apiKey` is absent. Lets a machine-local overlay name a credential without
   * embedding it (e.g. a token file another tool already maintains) — `~` expands
   * to the running user's home. An unreadable file is logged and ignored,
   * never thrown.
   */
  apiKeyFile?: string;
  model: string;
  fallbackModel?: string;
  /**
   * Additional fallback models, tried in order after `fallbackModel`, once
   * `model` has failed. `fallbackModel` stays the first-tried fallback for
   * backward compatibility; this list is where a second (third, ...) tier
   * goes. A link fails when it is unreachable, errors, or replies with
   * something that does not parse as a verdict; each failure is logged before
   * the next is tried, and the whole chain failing closes the verdict.
   */
  fallbackModels?: string[];
  /** Cheaper model asked first; its allow is final, its deny is re-asked of `model`. */
  triageModel?: string;
  /** One request's timeout (default 15000). */
  timeoutMs?: number;
  /**
   * The whole chain's deadline: triage, primary and every fallback together
   * (default 18000, under the 20 s agy gives a hook). Each request gets only
   * the time left; once it is spent the chain stops and fails closed as a
   * transient error, so a retry asks again.
   */
  totalTimeoutMs?: number;
  /** Completion budget; the reply is one short JSON object (default 120). */
  maxTokens?: number;
  /**
   * Extra fields merged into every chat-completion request, after the
   * per-route defaults that switch a model's hidden reasoning off. Set a key
   * to null to remove a default.
   */
  extraBody?: Record<string, unknown>;
  /** Cap on script content shown to the model (default 2000 chars). */
  maxFileChars?: number;
  /** Optional domain-specific instructions appended to the classifier prompt. */
  instructionsAppend?: string;
  /** Where uploads may go (see `AppConfig.sanctionedRemotes`); named in the prompt's exfiltration harm. */
  sanctionedRemotes?: string[];
  /** `PolicyConfig.protectedBranches`, named in the prompt's data-destruction harm. */
  protectedBranches?: string[];
}

export interface PolicyConfig {
  denyMode: "both" | "auto-retry" | "ask-user";
  consecutiveThreshold: number;
  slidingWindowMs: number;
  instructAgentOnDenial: boolean;
  /**
   * Nobody can answer a prompt on this machine. An escalation then becomes a
   * denial that tells the agent to stop and report, instead of a permission
   * left pending (or auto-rejected by `opencode run`) as if the user had
   * declined.
   */
  headless: boolean;
  /**
   * A script whose content is byte-identical to its repo's remote default
   * branch went through that branch's merge gate; allow it without the model
   * when the line is exactly the narrow shape `ScriptInvocation.plain`
   * describes (the script run on its own, plain arguments, nothing else).
   */
  trustLandedScripts: boolean;
  /**
   * Minutes to wait for the user to answer an escalation before auto-denying (default: 5).
   */
  escalationTimeoutMinutes?: number;
  /**
   * Optional domain-specific instructions appended to the classifier prompt.
   */
  instructionsAppend?: string;
  /**
   * Branches a force-push or deletion on a remote counts as data destruction
   * for, and that a plain `git push` is never fast-allowed to; also the
   * branches script provenance tries, in order, when a remote names no
   * default branch. Default `["main", "master"]`.
   */
  protectedBranches?: string[];
}

export interface RulesConfig {
  fastDeny?: string[];
  fastAllow?: string[];
  /** Path prefixes a fast-allowed command may redirect output into (default: /tmp/); see `isScratchRedirect` for what else a target must be. */
  scratchWriteRoots?: string[];
}

export interface TelemetryConfig {
  enabled: boolean;
  /** Empty means ~/.config/auto-classifier/telemetry.jsonl. */
  path: string;
  /** Past this many bytes the file moves to `<path>.1`, replacing any older one; 0 never rotates. Default 50 MB. */
  maxBytes?: number;
}

import type { CommandContext } from "./context/command-context.js";

/** TypeSafe Jev, a System One model; the gate asks it instead of a chat model when `llm.provider` is `"jev"`. */
export interface JevConfig {
  /** API root; the request goes to `<baseUrl>/v1/systemone`. */
  baseUrl?: string;
  /** Bearer key. Unused when `command` is set. */
  apiKey?: string;
  /** Helper argv that takes the request body on stdin and prints the response; lets a root-only key stay out of this process. */
  command?: string[];
  model?: string;
  /** A risk question at or above this probability denies (default 0.7). */
  riskThreshold?: number;
  /** An allow verdict below this confidence denies (default 0.6), unless every risk is below `lowRiskCeiling`. */
  minConfidence?: number;
  /** Every risk below this counts as quiet (default 0.2). */
  lowRiskCeiling?: number;
  /** With every risk quiet, an allow verdict at this p(allow) or more is enough (default 0.6), whatever its confidence. */
  lowRiskMinAllow?: number;
  timeoutMs?: number;
  /** Optional domain-specific instructions appended to Jev criteria. */
  instructionsAppend?: string;
  /** Where uploads may go (see `AppConfig.sanctionedRemotes`); named in the exfiltration question. */
  sanctionedRemotes?: string[];
  /** `PolicyConfig.protectedBranches`, named in the data-destruction question and the verdict's deny criteria. */
  protectedBranches?: string[];
}

export interface AgyConfig {
  /**
   * Inside tmux, press Enter on agy's own permission prompt for a command the
   * gate allowed, so that with `toolPermission: "request-review"` the only
   * prompts left are the gate's escalations. Default false.
   */
  autoAcceptInTmux?: boolean;
  /**
   * What the gate does with its own escalation when agy will approve it
   * without a prompt (toolPermission always-proceed, in settings.json or in
   * the running agy, or --dangerously-skip-permissions). "run" (default): the
   * user chose no prompts, so it runs, logged and recorded in telemetry
   * with source "always-proceed". "stop": deny it and tell the agent to stop
   * and ask the user. This decides only for an escalation the model actually
   * raised: one the gate raised (`gateRaised`: a rule, or a model that could
   * not be reached) is denied either way, because only the user may decide it.
   */
  alwaysProceedEscalations?: "run" | "stop";
}

/** What the gate itself established about a command before asking the model; never taken from the command. */
export interface GateFacts {
  /** Uploads the command makes that the gate resolved and found sanctioned, described. */
  sanctionedUploads?: string[];
  /** Where the command runs: cwd, its repository and remotes, where deleted paths land. */
  context?: CommandContext;
}

export interface AppConfig {
  /**
   * Host patterns uploads may go to: an exact host, a `*.suffix` wildcard, a
   * host plus path prefix (`github.com/octo-org/`), or an IPv4 CIDR range.
   * Loopback is always sanctioned and needs no entry; an upload anywhere else
   * is stopped before the model. The inline `sanctionedRemotes` array and the
   * entries of the JSON file `sanctionedRemotesFile` names, merged.
   */
  sanctionedRemotes: string[];
  llm: LlmConfig;
  jev: JevConfig;
  policy: PolicyConfig;
  rules: RulesConfig;
  telemetry: TelemetryConfig;
  agy?: AgyConfig;
}

export interface FileContext {
  path: string;
  content: string;
  /** One line on where the file came from (tracked, modified, untracked, ...). */
  provenance?: string;
  /** `content` is a head-slice: the file is longer than what is shown. */
  truncated?: boolean;
  /** The file's true length in characters, present when `truncated` is true. */
  originalLength?: number;
  /**
   * Present when the gate withheld this file's contents from the model (one of
   * its own files, or a credential-looking path): its size in bytes. `content`
   * is then only a note saying so. An executed file withheld is floored like a
   * truncated one.
   */
  withheldBytes?: number;
  /**
   * Whether this file is the program the command runs. `true` (or absent, the
   * conservative default) means its content is executed, so a head-slice may
   * hide a dangerous line past the cut and its allow must be floored.
   * `false` means the command merely reads the file as data -- the command is
   * what is judged, and truncating it hides no executed line.
   */
  executed?: boolean;
  /** Additional files referenced in the command line (e.g. via flags or file extensions). */
  attachedFiles?: Array<{
    path: string;
    content: string;
    truncated?: boolean;
    originalLength?: number;
    /** As on `FileContext.executed`: `false` for an incidental reference. */
    executed?: boolean;
  }>;
  /**
   * `"script"` (default): a file the command is about to run or read, shown
   * as supporting context alongside a shell command. `"file-write"`: the
   * verdict IS the write/edit itself -- `content` is the change (a write's
   * new content, or an edit's before/after excerpt), not a script the model
   * only needs for background. `buildUserPrompt` frames the two differently.
   */
  kind?: "script" | "file-write";
}

/** Tokens the model calls behind one classification spent, summed across triage and fallbacks. */
export interface Usage {
  input_tokens: number;
  output_tokens: number;
  calls: number;
}

export interface ClassificationResult {
  allow: boolean;
  reason: string;
  /** Absent when no model was asked, or the provider reported no usage. */
  usage?: Usage;
  /** Jev's raw answers and the concrete model version that gave them, for re-scoring thresholds offline. */
  jev?: { model?: string; answers: Record<string, unknown> };
  source: "fast-rule" | "llm" | "fallback" | "triage" | "error";
  ruleId?: string;
}

export interface DecisionOutcome {
  decision: "allow" | "deny" | "ask" | "force_ask";
  reason?: string;
  consecutiveCount: number;
  escalated: boolean;
  /**
   * Set when a deterministic rule refused the call (self-protection,
   * `rules.fastDeny`, an unsanctioned upload, a protected or credential-looking
   * path) rather than the model. Its escalation exists only so that a person
   * can overrule the rule, so an adapter refuses it wherever no prompt is sure
   * to reach one.
   */
  ruleRefusal?: boolean;
  /**
   * Set when the gate, not a model's judgment, raised this escalation: a
   * rule's refusal (`ruleRefusal`), a file write the file-tool ladder sends
   * to a person, a model's allow of a file it was not shown whole, or a model
   * that could not be reached. It exists only for a person to decide, so an
   * adapter refuses it wherever nobody can be asked, whatever
   * `agy.alwaysProceedEscalations` says.
   */
  gateRaised?: boolean;
}

export interface AgyToolCall {
  name: string;
  args?: {
    CommandLine?: string;
    Cwd?: string;
    [key: string]: unknown;
  };
}

export interface AgyPreToolUseInput {
  toolCall?: AgyToolCall;
  conversationId?: string;
  stepIdx?: number;
  workspacePaths?: string[];
  modelName?: string;
  [key: string]: unknown;
}

export interface AgyPreToolUseOutput {
  decision: "allow" | "deny" | "ask" | "force_ask";
  reason?: string;
  permissionOverrides?: string[];
  overwrite?: Record<string, unknown>;
}
