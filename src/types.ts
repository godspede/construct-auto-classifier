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
  /** Cheaper model asked first; its allow is final, its deny is re-asked of `model`. */
  triageModel?: string;
  timeoutMs?: number;
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
}

export interface PolicyConfig {
  denyMode: "both" | "auto-retry" | "ask-user";
  consecutiveThreshold: number;
  slidingWindowMs: number;
  instructAgentOnDenial: boolean;
  /**
   * No operator can answer a prompt on this box. An escalation then becomes a
   * denial that tells the agent to stop and report, instead of a permission
   * left pending (or auto-rejected by `opencode run`) as if the operator had
   * declined.
   */
  headless: boolean;
  /**
   * A script whose content is byte-identical to its repo's remote default
   * branch went through that branch's merge gate; allow it without the model.
   */
  trustLandedScripts: boolean;
}

export interface RulesConfig {
  fastDeny?: string[];
  fastAllow?: string[];
  /** Path prefixes a fast-allowed command may redirect output into (default: /tmp/). */
  scratchWriteRoots?: string[];
}

export interface TelemetryConfig {
  enabled: boolean;
  /** Empty means ~/.config/auto-classifier/telemetry.jsonl. */
  path: string;
}

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
  /** An allow verdict below this confidence denies (default 0.6). */
  minConfidence?: number;
  timeoutMs?: number;
}

export interface AgyConfig {
  /**
   * Inside tmux, press Enter on agy's own permission prompt for a command the
   * gate allowed, so that with `toolPermission: "request-review"` the only
   * prompts left are the gate's escalations. Default false.
   */
  autoAcceptInTmux?: boolean;
}

export interface AppConfig {
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
