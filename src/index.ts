import { loadConfig } from "./config.js";
import { evaluateFastRules, DEFAULT_SCRATCH_WRITE_ROOTS } from "./rules/fast-rules.js";
import { unmodelledConstructs } from "./rules/command-shape.js";
import { isGateDataPath, isGatePath, isSecretSearchScope, isSecretTarget, searchScopeCovers } from "./rules/self-protection.js";
import { sensitiveWorkspaceWrite } from "./rules/file-write.js";
import { isSensitiveWriteTarget } from "./rules/sensitive-write.js";
import { isSymlinkTarget, isWithinRoot, rootForms, targetLocations, targetSpellings } from "./rules/workspace.js";
import { parsePatchTargets } from "./rules/patch.js";
import { LlmClient, type Classifier } from "./classifier/client.js";
import { JevClient } from "./classifier/jev-client.js";
import { StateManager } from "./state/state-manager.js";
import { scriptProvenance, type GitRunner } from "./context/script-provenance.js";
import { findReferencedFiles, type ReferencedFile } from "./context/file-references.js";
import { writeTelemetry, snippetOf } from "./telemetry.js";
import { detectInjectionAttempt } from "./rules/injection-detection.js";
import { checkUploads, parseSanctioned, type SanctionedEntry } from "./rules/uploads.js";
import { buildCommandContext } from "./context/command-context.js";
import { VERSION } from "./version.js";
import crypto from "node:crypto";
import path from "node:path";
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
export { findReferencedFiles, type ReferencedFile } from "./context/file-references.js";
export { VERSION } from "./version.js";
export { log } from "./log.js";

/** Seams a caller may replace: the LLM (tests script it) and where state lives. */
export interface AutoClassifierDeps {
  classifier?: Classifier;
  stateManager?: StateManager;
  /** How git is run for script provenance and for resolving a push's remote; tests may script it. */
  git?: GitRunner;
}

export interface EvaluateOptions {
  /** Directory the command will run in; relative script paths resolve against it. */
  cwd?: string;
  /** The harness's own id for this tool call, for the telemetry row. */
  callId?: string;
}

/** OpenCode's file-tool names this classifier judges directly (no shell command to parse). */
export type FileTool = "read" | "write" | "edit";

/** OpenCode's directory-scoped search tools -- a `path` argument, never a target file to open. */
export type SearchTool = "grep" | "glob" | "list";

export interface FileOpOptions {
  /** The session's workspace root; the boundary the file-tool guard's fast-allow checks against. */
  cwd?: string;
  /** The harness's own id for this tool call, for the telemetry row. */
  callId?: string;
}

export interface SearchScopeOptions extends FileOpOptions {
  /** The search's own pattern (grep's regex, glob's glob), shown to the model when the scope needs one. */
  pattern?: string;
}

/**
 * The most of a script or written file the chat model's prompt shows
 * (`src/classifier/prompt.ts` slices the file there), whatever
 * `llm.maxFileChars` says. Jev is shown `llm.maxFileChars`.
 */
export const CHAT_PROMPT_FILE_CHARS = 8000;

/** A short hash of everything a model verdict was given, the key a remembered allow must match. */
function shownKey(shown: Record<string, unknown>): string {
  return crypto.createHash("sha1").update(JSON.stringify(shown)).digest("hex").slice(0, 16);
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
  private sanctioned: SanctionedEntry[];

  constructor(config?: AppConfig, deps: AutoClassifierDeps = {}) {
    this.config = config || loadConfig();
    this.llmClient = deps.classifier ?? createClassifier(this.config);
    this.stateManager =
      deps.stateManager ??
      new StateManager(this.config.policy.slidingWindowMs, this.config.policy.consecutiveThreshold);
    this.git = deps.git;
    this.sanctioned = parseSanctioned(this.config.sanctionedRemotes);
  }

  getConfig(): AppConfig {
    return this.config;
  }

  /**
   * How much of a file the model will really be shown: `llm.maxFileChars`,
   * and for a chat model no more than its prompt shows. Content is cut here,
   * so anything past what the model sees is flagged as cut short.
   */
  private fileCharCap(): number {
    const max = this.config.llm.maxFileChars ?? 2000;
    return this.config.llm.provider === "jev" ? max : Math.min(max, CHAT_PROMPT_FILE_CHARS);
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
        tool: "bash",
      });
    }
    return decided.outcome;
  }

  /**
   * Judge one OpenCode `read`/`write`/`edit` call directly -- these arrive
   * with a target path and (for write/edit) the change itself, never a shell
   * command to parse, so they skip `evaluateFastRules`/`scriptProvenance`
   * entirely and go through their own deterministic-first ladder instead.
   * Every rule is checked on the path as written AND on where the write
   * really lands, every symlink followed (`targetLocations`), and the
   * stricter outcome wins:
   *
   *   1. `read` of a credential-looking path (`isSecretPath`, the same
   *      `SECRET_PATH` regex a fast-allowed `cat` cannot vouch for) -> deny.
   *      Every other read is routine and reversible -> allow, no model call,
   *      in or out of the workspace.
   *   2. `write`/`edit` of the classifier's own gate (`isGatePath`: its
   *      config, plugin, session state and code) or a credential-looking
   *      path -> deny. Neither check is config-driven, for the same reason
   *      `self-protection.ts` gives for bash.
   *   3. `write`/`edit` inside the workspace under a path agy's file tools
   *      escalate (harness and MCP config, git internals, CI workflows;
   *      `sensitiveWorkspaceWrite`) -> force_ask, no model.
   *   4. `write`/`edit` whose every location lies inside the session's own
   *      workspace (`cwd`) or a configured scratch root
   *      (`rules.scratchWriteRoots`, default `/tmp/`) -> allow, no model,
   *      unless it is a sensitive startup location (`isSensitiveWriteTarget`).
   *      A target that is itself a symlink never counts as scratch.
   *   5. Anything else reaches the model with the target path and a bounded,
   *      truncated excerpt of the change -- same retry/cache/escalation path
   *      (`handleDenial`, the sliding-window allow cache) a bash command
   *      gets, and the same never-allow-on-truncation rule (`truncatedOutcome`).
   */
  async evaluateFileOp(
    tool: FileTool,
    filePath: string,
    sessionId: string = "default-session",
    content: string | undefined = undefined,
    opts: FileOpOptions = {}
  ): Promise<DecisionOutcome> {
    const started = Date.now();
    const decided = await this.decideFileOp(tool, filePath, sessionId, content, opts);
    const injectionPattern = detectInjectionAttempt(`${tool} ${filePath}`) ?? detectInjectionAttempt(decided.fileContext?.content ?? "");
    writeTelemetry(this.config.telemetry, {
      id: opts.callId ?? "",
      session: sessionId,
      command: `${tool} ${filePath}`,
      file_path: filePath,
      file_snippet: snippetOf(decided.fileContext),
      decision: decided.outcome.decision,
      source: decided.source,
      reason: decided.outcome.reason ?? "",
      latency_ms: Date.now() - started,
      model: decided.source === "llm" || decided.source === "fallback" || decided.source === "triage" || decided.source === "error" || decided.source === "truncated" ? (this.config.llm.provider === "jev" ? decided.jev?.model ?? this.config.jev.model ?? null : this.config.llm.model) : null,
      injection_attempt: injectionPattern !== null,
      injection_pattern: injectionPattern,
      cwd: opts.cwd ?? null,
      tool,
    });
    return decided.outcome;
  }

  private async decideFileOp(
    tool: FileTool,
    filePath: string,
    sessionId: string,
    content: string | undefined,
    opts: FileOpOptions
  ): Promise<Decided> {
    // Denials are counted per (tool, path): a `read` and a `write` of the
    // same path are different attempts, and a colon never appears in either
    // half so the key round-trips through normalizeCommand's shell-shape
    // parser without being mistaken for a redirect or an env assignment.
    const key = `${tool}:${filePath}`;

    if (tool === "read") {
      if (isSecretTarget(filePath, opts.cwd)) {
        return { outcome: this.refuseByRule(sessionId, key, `Reads a credential-looking path (${filePath})`), source: "secret-deny" };
      }
      return {
        outcome: { decision: "allow", reason: "Read of a non-secret path", consecutiveCount: 0, escalated: false },
        source: "read-allow",
      };
    }

    // tool is "write" or "edit" from here.
    if (isGatePath(filePath, opts.cwd) || isSecretTarget(filePath, opts.cwd)) {
      const why = isGatePath(filePath, opts.cwd) ? "the classifier's own gate" : "a credential-looking path";
      return { outcome: this.refuseByRule(sessionId, key, `${tool} targets ${why} (${filePath})`), source: "protected-deny" };
    }

    // Inside the workspace, the places a write changes what runs or who is
    // trusted (harness and MCP config, git internals and hooks, CI workflows)
    // escalate to the operator with no model call, exactly as agy's file
    // tools do (rules/file-write.ts).
    const sensitive = this.sensitiveInWorkspace(filePath, opts.cwd);
    if (sensitive) {
      return { outcome: this.escalateWrite(`This writes ${filePath}: ${sensitive}.`), source: "sensitive-escalate" };
    }

    // A sensitive system/startup location is judged by the model even when
    // it resolves inside the workspace or a scratch root -- see
    // sensitive-write.ts's own header for why "inside the workspace" is not
    // evidence of safety here (OpenCode started with cwd `~` makes
    // `~/.bashrc` "inside the workspace" by the letter of that check alone).
    // This check therefore runs BEFORE, and skips, both fast-allow checks
    // below, rather than after them.
    if (!this.isSensitiveTarget(filePath, opts.cwd)) {
      // With no workspace known (OpenCode handed the plugin no `directory`),
      // nothing is inside one: only an absolute scratch-root target is placed,
      // and anything else goes to the model, exactly as a patch with no
      // workspace does.
      const place = this.placeWrite(filePath, opts.cwd);
      if (place === "workspace") {
        return {
          outcome: { decision: "allow", reason: `${tool} stays inside the session's workspace`, consecutiveCount: 0, escalated: false },
          source: "workspace-allow",
        };
      }
      if (place === "scratch") {
        return {
          outcome: { decision: "allow", reason: `${tool} targets a configured scratch root`, consecutiveCount: 0, escalated: false },
          source: "scratch-allow",
        };
      }
    }

    // Outside the workspace, a sensitive location, or not otherwise
    // deterministically covered: the same retry-dedup, sliding-window allow
    // cache, and model path a bash command outside a fast rule gets.
    return this.resolveViaModel(key, `${tool} ${filePath}`, content ?? "", sessionId, opts.cwd);
  }

  /**
   * The shared tail of every file-tool judgment that reaches the model: a
   * retry of a still-denied key skips straight to `handleDenial`, an
   * identical excerpt inside the sliding window is remembered, and
   * everything else is one bounded, truncation-guarded classification call.
   * `label` is both the classify() "command" text and the `FileContext.path`
   * shown in the prompt -- a real path for a single write/edit, or a
   * human-readable summary (e.g. every target a patch touches) when there
   * is no one path to show.
   */
  private async resolveViaModel(key: string, label: string, content: string, sessionId: string, cwd: string | undefined, provenance?: string): Promise<Decided> {
    const prior = this.stateManager.recentDenial(sessionId, key);
    if (prior && !prior.transient) {
      return { outcome: this.handleDenial(sessionId, key, prior.reason), source: "retry" };
    }

    const maxChars = this.fileCharCap();
    const truncated = content.length > maxChars;
    const fileContext: FileContext = {
      path: label,
      content: truncated ? content.slice(0, maxChars) : content,
      truncated,
      originalLength: truncated ? content.length : undefined,
      kind: "file-write",
      provenance,
    };

    // A relative target names a different file from another workspace, so
    // the workspace is part of what a remembered allow vouched for.
    const contextKey = shownKey({ cwd: cwd ?? null, fileContext });
    const cached = this.stateManager.recentAllow(sessionId, key, contextKey);
    if (cached) {
      return {
        outcome: { decision: "allow", reason: `${cached.reason} (same verdict as earlier in this session)`, consecutiveCount: 0, escalated: false },
        source: "cache",
        fileContext,
      };
    }

    const result: ClassificationResult = await this.llmClient.classify(label, fileContext, sessionId);

    const truncatedOutcome = this.truncatedOutcome(fileContext, result);
    if (truncatedOutcome) {
      return { outcome: truncatedOutcome, source: "truncated", fileContext };
    }

    if (result.allow) {
      this.stateManager.recordAllow(sessionId, key, { exploratory: false, reason: result.reason, contextKey });
      return { outcome: { decision: "allow", reason: result.reason, consecutiveCount: 0, escalated: false }, source: result.source, fileContext };
    }

    return { outcome: this.modelDenial(sessionId, key, result), source: result.source, fileContext };
  }

  /**
   * Judge OpenCode's directory-scoped search tools (`grep`/`glob`/`list`,
   * each taking an optional `path` to scope a recursive walk; an omitted path
   * scopes the search to the session's own active location, its workspace).
   * A scope inside a credential directory (`isSecretSearchScope`, which covers
   * both a `SECRET_PATH` directory like `.ssh` and the narrower auth-store
   * directories a single-filename match cannot see, e.g. `.config/opencode`)
   * or inside the gate's own files (`isGateDataPath`) is denied. A scope that
   * CONTAINS one of those places (`searchScopeCovers`: `~`, `~/.config`, `/`)
   * goes to the model, told what it would sweep up (OpenCode's grep reads
   * hidden files too). Anything else is routine, exactly as a plain
   * `read` of a workspace file, and is allowed with no model call.
   */
  async evaluateSearchScope(tool: SearchTool, searchPath: string | undefined, sessionId: string = "default-session", opts: SearchScopeOptions = {}): Promise<DecisionOutcome> {
    const started = Date.now();
    const decided = await this.decideSearchScope(tool, searchPath, sessionId, opts);
    const injectionPattern = detectInjectionAttempt(`${tool} ${searchPath ?? "(active location)"}`);
    writeTelemetry(this.config.telemetry, {
      id: opts.callId ?? "",
      session: sessionId,
      command: `${tool} ${searchPath ?? "(active location)"}`,
      file_path: searchPath ?? null,
      file_snippet: null,
      decision: decided.outcome.decision,
      source: decided.source,
      reason: decided.outcome.reason ?? "",
      latency_ms: Date.now() - started,
      model: decided.source === "llm" || decided.source === "fallback" || decided.source === "triage" || decided.source === "error" ? (this.config.llm.provider === "jev" ? decided.jev?.model ?? this.config.jev.model ?? null : this.config.llm.model) : null,
      injection_attempt: injectionPattern !== null,
      injection_pattern: injectionPattern,
      cwd: opts.cwd ?? null,
      tool,
    });
    return decided.outcome;
  }

  private async decideSearchScope(tool: SearchTool, searchPath: string | undefined, sessionId: string, opts: SearchScopeOptions): Promise<Decided> {
    const key = `${tool}:${searchPath ?? "(active location)"}`;
    if (searchPath && targetSpellings(searchPath, opts.cwd).some(isSecretSearchScope)) {
      return {
        outcome: this.refuseByRule(sessionId, key, `${tool} scoped into a credential-looking location (${searchPath})`),
        source: "secret-deny",
      };
    }
    if (searchPath && isGateDataPath(searchPath, opts.cwd)) {
      return {
        outcome: this.refuseByRule(sessionId, key, `${tool} scoped into the classifier's own files (${searchPath})`),
        source: "protected-deny",
      };
    }
    const scope = searchPath ?? opts.cwd;
    const covers = scope ? searchScopeCovers(scope, opts.cwd) : null;
    if (!covers) {
      return {
        outcome: { decision: "allow", reason: `${tool} scope is not credential-looking`, consecutiveCount: 0, escalated: false },
        source: "search-allow",
      };
    }

    const prior = this.stateManager.recentDenial(sessionId, key);
    if (prior && !prior.transient) {
      return { outcome: this.handleDenial(sessionId, key, prior.reason), source: "retry" };
    }
    const label = `opencode ${tool} tool scoped at ${scope}${tool === "grep" ? ", which searches file contents, hidden files included" : ""}${opts.pattern ? `, pattern ${JSON.stringify(opts.pattern)}` : ""}; that scope contains ${covers}`;
    const contextKey = shownKey({ cwd: opts.cwd ?? null, label });
    const cached = this.stateManager.recentAllow(sessionId, key, contextKey);
    if (cached) {
      return {
        outcome: { decision: "allow", reason: `${cached.reason} (same verdict as earlier in this session)`, consecutiveCount: 0, escalated: false },
        source: "cache",
      };
    }
    const result = await this.llmClient.classify(label, undefined, sessionId);
    if (result.allow) {
      this.stateManager.recordAllow(sessionId, key, { exploratory: false, reason: result.reason, contextKey });
      return { outcome: { decision: "allow", reason: result.reason, consecutiveCount: 0, escalated: false }, source: result.source, usage: result.usage, jev: result.jev };
    }
    return { outcome: this.modelDenial(sessionId, key, result), source: result.source, usage: result.usage, jev: result.jev };
  }

  /**
   * Judge an `apply_patch`/`patch` call: OpenCode's multi-file diff tool,
   * whose `patchText` can add, update, delete, or move several files in one
   * call. Every target `parsePatchTargets` finds runs through the same
   * write/edit predicates a single-file `write`/`edit` gets (protected/secret
   * paths, sensitive locations, workspace/scratch membership); the strictest
   * outcome across all of them wins, and a deny on any one target denies the
   * whole patch outright rather than applying the rest. Only when EVERY
   * target clears the deterministic ladder does the patch skip the model;
   * otherwise one call reviews the whole `patchText` at once, rather than one
   * call per target. A `patchText` `parsePatchTargets` cannot resolve into at
   * least one target never gets the deterministic allow either way -- it
   * always reaches the model (or, on repeat denial, the operator), the same
   * as any other write the ladder cannot place inside the workspace.
   */
  async evaluatePatch(patchText: string, sessionId: string = "default-session", opts: FileOpOptions = {}): Promise<DecisionOutcome> {
    const started = Date.now();
    const decided = await this.decidePatch(patchText, sessionId, opts);
    const targets = decided.targets;
    const injectionPattern = detectInjectionAttempt(targets ? `patch ${targets.join(", ")}` : "patch (unparseable)") ?? detectInjectionAttempt(decided.fileContext?.content ?? "");
    writeTelemetry(this.config.telemetry, {
      id: opts.callId ?? "",
      session: sessionId,
      command: targets ? `patch ${targets.join(", ")}` : "patch (unparseable)",
      file_path: targets ? targets.join(", ") : null,
      file_snippet: snippetOf(decided.fileContext),
      decision: decided.outcome.decision,
      source: decided.source,
      reason: decided.outcome.reason ?? "",
      latency_ms: Date.now() - started,
      model: decided.source === "llm" || decided.source === "fallback" || decided.source === "triage" || decided.source === "error" || decided.source === "truncated" ? (this.config.llm.provider === "jev" ? decided.jev?.model ?? this.config.jev.model ?? null : this.config.llm.model) : null,
      injection_attempt: injectionPattern !== null,
      injection_pattern: injectionPattern,
      cwd: opts.cwd ?? null,
      tool: "patch",
    });
    return decided.outcome;
  }

  private async decidePatch(patchText: string, sessionId: string, opts: FileOpOptions): Promise<Decided & { targets?: string[] }> {
    const targets = parsePatchTargets(patchText);
    const key = `patch:${crypto.createHash("sha1").update(patchText).digest("hex").slice(0, 16)}`;

    if (!targets) {
      const decided = await this.resolveViaModel(key, "patch (unparsed)", patchText, sessionId, opts.cwd, "patchText could not be parsed into individual file targets; judge the whole patch");
      return { ...decided, targets: undefined };
    }

    for (const target of targets) {
      if (isGatePath(target, opts.cwd) || isSecretTarget(target, opts.cwd)) {
        const why = isGatePath(target, opts.cwd) ? "the classifier's own gate" : "a credential-looking path";
        return { outcome: this.refuseByRule(sessionId, key, `patch targets ${why} (${target})`), source: "protected-deny", targets };
      }
    }
    for (const target of targets) {
      const sensitive = this.sensitiveInWorkspace(target, opts.cwd);
      if (sensitive) {
        return { outcome: this.escalateWrite(`This patch writes ${target}: ${sensitive}.`), source: "sensitive-escalate", targets };
      }
    }

    const allDeterministicallyAllowed = targets.every((target) => !this.isSensitiveTarget(target, opts.cwd) && this.placeWrite(target, opts.cwd) !== null);
    if (allDeterministicallyAllowed) {
      return {
        outcome: { decision: "allow", reason: `patch touches only workspace/scratch targets (${targets.join(", ")})`, consecutiveCount: 0, escalated: false },
        source: "workspace-allow",
        targets,
      };
    }

    const decided = await this.resolveViaModel(key, `patch ${targets.join(", ")}`, patchText, sessionId, opts.cwd);
    return { ...decided, targets };
  }

  /**
   * Whether a write to `target` may skip the model by where it lands:
   * "workspace" when every location it names (`targetLocations`: its letters,
   * and where the kernel would write it, every symlink followed) lies inside
   * the session's workspace; "scratch" when each lies inside the workspace or
   * a configured scratch root, and the target is not itself a symlink (a link
   * in a shared scratch directory can be re-pointed after the gate looked);
   * otherwise null. A relative target is placed only against the workspace,
   * never against this process's own working directory, so with no workspace
   * only an absolute target is placed at all.
   */
  private placeWrite(target: string, cwd: string | undefined): "workspace" | "scratch" | null {
    const locations = targetLocations(target, cwd);
    if (locations.length === 0) return null;
    const workspace = cwd && path.isAbsolute(cwd) ? rootForms(cwd) : [];
    const scratch = isSymlinkTarget(target, cwd)
      ? []
      : (this.config.rules.scratchWriteRoots ?? DEFAULT_SCRATCH_WRITE_ROOTS).filter((root) => path.isAbsolute(root)).flatMap(rootForms);
    let needsScratch = false;
    for (const loc of locations) {
      if (workspace.some((root) => isWithinRoot(loc, root))) continue;
      if (!scratch.some((root) => isWithinRoot(loc, root))) return null;
      needsScratch = true;
    }
    return needsScratch ? "scratch" : "workspace";
  }

  /** `isSensitiveWriteTarget` on the target as written and on every location it names. */
  private isSensitiveTarget(target: string, cwd: string | undefined): boolean {
    return targetSpellings(target, cwd).some(isSensitiveWriteTarget);
  }

  /**
   * Why a write to `target` inside the workspace `cwd` needs the operator, or
   * null when no location it names is one of those places inside it. Each
   * location is judged relative to the root form it lies in, so a link to
   * `.git/hooks` escalates exactly as `.git/hooks` does.
   */
  private sensitiveInWorkspace(target: string, cwd: string | undefined): string | null {
    if (!cwd || !path.isAbsolute(cwd)) return null;
    const roots = rootForms(cwd);
    for (const loc of targetLocations(target, cwd)) {
      for (const root of roots) {
        if (!isWithinRoot(loc, root)) continue;
        const what = sensitiveWorkspaceWrite(path.relative(root, loc).split(path.sep).join("/"));
        if (what) return what;
      }
    }
    return null;
  }

  /**
   * An escalation straight to the operator's prompt, as agy's file tools
   * escalate: no model call and no first denial. A headless session turns it
   * into a refusal in the adapter, like any other escalation, and, since a
   * rule raised it (`gateRaised`), so does agy approving its own prompts.
   */
  private escalateWrite(reason: string): DecisionOutcome {
    return { decision: "force_ask", reason: `⚠️ SAFETY ESCALATION: ${reason}`, consecutiveCount: 0, escalated: true, gateRaised: true };
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

    // A line holding syntax the analyser does not fully model is never allowed
    // without the model: fast allow refuses it (its reasons are tells), and
    // neither landed-script trust nor the cache below may vouch for it. The
    // deterministic denials still see it.
    const unmodelled = unmodelledConstructs(trimmed).length > 0;

    // 1. Fast Rules Evaluation
    const fastRule = evaluateFastRules(trimmed, this.config.rules, opts.cwd ?? process.cwd());
    if (fastRule?.matched === "deny") {
      return { outcome: this.refuseByRule(sessionId, trimmed, `Critical safety rule matched (${fastRule.pattern})`), source: "fast-deny" };
    }

    // 1b. An upload to a destination nobody sanctioned is stopped here, ahead
    // of any fast-allow (a `git push origin feature` rule vouches for the verb,
    // not for where origin points) and without asking the model, so stopping
    // it never depends on the model's confidence.
    const uploads = checkUploads(trimmed, { cwd: opts.cwd ?? process.cwd(), sanctioned: this.sanctioned, git: this.git });
    if (uploads.unsanctioned) {
      return { outcome: this.refuseByRule(sessionId, trimmed, uploads.unsanctioned), source: "upload" };
    }

    if (fastRule?.matched === "allow") {
      // Fast-allowed means structurally read-only: it must not reset the
      // consecutive-denial counter, or an agent could interleave `ls` between
      // retries forever.
      this.stateManager.recordAllow(sessionId, trimmed, { exploratory: true });
      return {
        outcome: { decision: "allow", reason: `Fast-allow rule matched (${fastRule.pattern})`, consecutiveCount: 0, escalated: false },
        source: "fast-allow",
      };
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
      const prov = scriptProvenance(trimmed, opts.cwd ?? process.cwd(), { maxChars: this.fileCharCap(), git: this.git, protectedBranches: this.config.policy.protectedBranches });
      if (prov) {
        // Only a plain run of a landed script (no env prefix, no output
        // redirect) is what the branch's review vouched for.
        if (prov.landed && prov.plain && !unmodelled && this.config.policy.trustLandedScripts) {
          this.stateManager.recordAllow(sessionId, trimmed, { exploratory: false });
          return {
            outcome: { decision: "allow", reason: `Landed script: ${prov.summary}`, consecutiveCount: 0, escalated: false },
            source: "landed",
            fileContext: { path: prov.path, content: "", provenance: prov.summary },
          };
        }
        fileContext = { path: prov.path, content: prov.content ?? "", provenance: prov.summary, truncated: prov.truncated, originalLength: prov.originalLength, withheldBytes: prov.withheldBytes };
      }
    }

    // Attach any other files referenced in the command line (via -f, --file, or known extensions)
    const referenced = findReferencedFiles(trimmed, opts.cwd ?? process.cwd(), { maxChars: this.fileCharCap() });
    if (referenced.length > 0) {
      if (!fileContext) {
        fileContext = {
          path: referenced[0]!.path,
          content: referenced[0]!.content,
          truncated: referenced[0]!.truncated,
          originalLength: referenced[0]!.originalLength,
          executed: referenced[0]!.executed,
          attachedFiles: referenced,
        };
      } else {
        fileContext.attachedFiles = referenced.filter((f) => f.path !== fileContext!.path);
      }
    }

    // 4. The model only sees the text it is shown, so the same text inside the
    // window gets the same answer without asking again. "The same text" is
    // everything it is shown: the command, where it runs, the facts gathered
    // there, and every file attached.
    const cwd = opts.cwd ?? process.cwd();
    const context = buildCommandContext(trimmed, cwd, { git: this.git, sanctioned: this.sanctioned });
    const contextKey = shownKey({ cwd, context, sanctionedUploads: uploads.sanctioned, fileContext: fileContext ?? null });
    const cached = unmodelled ? undefined : this.stateManager.recentAllow(sessionId, trimmed, contextKey);
    if (cached) {
      return {
        outcome: { decision: "allow", reason: `${cached.reason} (same verdict as earlier in this session)`, consecutiveCount: 0, escalated: false },
        source: "cache",
        fileContext,
      };
    }

    // 5. LLM Classification Evaluation
    const result: ClassificationResult = await this.llmClient.classify(trimmed, fileContext, sessionId, { sanctionedUploads: uploads.sanctioned, context });

    const truncatedOutcome = this.truncatedOutcome(fileContext, result);
    if (truncatedOutcome) {
      return { outcome: truncatedOutcome, source: "truncated", fileContext, usage: result.usage, jev: result.jev };
    }

    if (result.allow) {
      this.stateManager.recordAllow(sessionId, trimmed, { exploratory: false, reason: result.reason, contextKey });
      return { outcome: { decision: "allow", reason: result.reason, consecutiveCount: 0, escalated: false }, source: result.source, fileContext, usage: result.usage, jev: result.jev };
    }

    // 6. LLM Denied Command
    return { outcome: this.modelDenial(sessionId, trimmed, result), source: result.source, fileContext, usage: result.usage, jev: result.jev };
  }

  /**
   * The model reasoned about a head-slice as though it were the whole file;
   * its allow says nothing about what it did not see, and must not become a
   * gate allow. This does not depend on the model noticing the truncation
   * marker in the prompt -- it is enforced here regardless, for a script
   * read via `decide()` and a file-write judged via `decideFileOp()` alike.
   * An executed file whose contents the gate withheld (`withheldBytes`: one
   * of its own files or a credential-looking path) was not seen at all, and
   * floors the same way.
   * A file the command merely READS (attached by `findReferencedFiles`,
   * `executed: false`) is data: a head-slice of it hides no executed line, so
   * it is not floored.
   * Ask when someone can answer; deny when nobody can, since an unanswerable
   * prompt on a headless machine is not a gate. The gate, not the model,
   * raised this ask, so it is marked `gateRaised`: an adapter never lets a
   * harness approve it by itself. Returns null when the guard does not apply
   * (no truncation, an incidental read, or the model already denied).
   */
  private truncatedOutcome(fileContext: FileContext | undefined, result: ClassificationResult): DecisionOutcome | null {
    if (!result.allow || !fileContext || fileContext.executed === false) return null;
    if (fileContext.withheldBytes !== undefined) {
      return {
        decision: this.config.policy.headless ? "deny" : "ask",
        reason: `The file's contents (${fileContext.withheldBytes} bytes) were withheld from the classifier, as one of the gate's own files or a credential-looking path; an allow of a file it could not see cannot be trusted. Model said: ${result.reason}`,
        consecutiveCount: 0,
        escalated: false,
        gateRaised: true,
      };
    }
    if (!fileContext.truncated) return null;
    return {
      decision: this.config.policy.headless ? "deny" : "ask",
      reason: `Content was truncated (showing ${fileContext.content.length} of ${fileContext.originalLength} characters) before the classifier saw it; a partial file cannot be safely allowed. Model said: ${result.reason}`,
      consecutiveCount: 0,
      escalated: false,
      gateRaised: true,
    };
  }

  /**
   * A deterministic rule's refusal: counted and escalated like any denial, so
   * that a person can overrule the rule at their own prompt, and marked
   * `ruleRefusal` and `gateRaised` so an adapter never lets a harness approve
   * that escalation by itself. With nobody at the keyboard (`policy.headless`)
   * it is a denial in every `denyMode`.
   */
  private refuseByRule(sessionId: string, key: string, rawReason: string): DecisionOutcome {
    const outcome = this.handleDenial(sessionId, key, rawReason);
    if (outcome.decision !== "deny" && this.config.policy.headless) {
      return {
        decision: "deny",
        reason: [
          `Action blocked by safety classifier, ${outcome.consecutiveCount} times: ${rawReason}.`,
          `This session is headless: nobody can answer a prompt here. Stop, and report to the user that this command needs their decision.`,
        ].join(" "),
        consecutiveCount: outcome.consecutiveCount,
        escalated: outcome.escalated,
        ruleRefusal: true,
        gateRaised: true,
      };
    }
    return { ...outcome, ruleRefusal: true, gateRaised: true };
  }

  /**
   * The model's answer was not an allow. When no model could be reached (an
   * error, a timeout, a chain with no fallback left) nobody judged the call,
   * so the escalation its fail-closed denials build up to is marked
   * `gateRaised`, as a rule's is: an adapter refuses it wherever nobody can
   * be asked.
   */
  private modelDenial(sessionId: string, key: string, result: ClassificationResult): DecisionOutcome {
    const outcome = this.handleDenial(sessionId, key, result.reason, result.source === "error");
    return result.source === "error" ? { ...outcome, gateRaised: true } : outcome;
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
          `This session is headless: nobody can answer a prompt here. Stop, and report to the user that this command needs their decision.`,
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
        ? ` (${remaining} attempt(s) remaining before the user is asked).`
        : this.config.policy.headless
          ? `. Running this exact command again will be blocked: nobody is present to approve it.`
          : `. Running this exact command again will be held for the user's approval, and it stays blocked if nobody is there to approve it.`;

    return [
      `Action blocked by safety classifier: ${rawReason}.`,
      `If this command is safe and strictly necessary, output a clear explanation to the user addressing why the classifier's concern does not apply and why this action is safe, then attempt the command again${next}`,
      `Otherwise, find a safer alternative.`,
    ].join(" ");
  }
}
