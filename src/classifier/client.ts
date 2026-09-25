import type { LlmConfig, ClassificationResult, FileContext, GateFacts, Usage } from "../types.js";
import { buildSystemPrompt, buildUserPrompt } from "./prompt.js";
import { log } from "../log.js";

/** A reply that parsed into no verdict: the model answered, but not in the shape asked for. */
class UnparseableReply extends Error {
  constructor(readonly verdict: { allow: false; reason: string }) {
    super(`unparseable reply: ${verdict.reason}`);
  }
}

/** The verdict in a reply, or an `UnparseableReply` carrying the fail-closed deny `parseClassificationResponse` returns. */
function parseVerdict(rawContent: string): { allow: boolean; reason: string } | UnparseableReply {
  let text = rawContent.trim();

  // Strip markdown fences ```json ... ``` if model wrapped it
  if (text.startsWith("```")) {
    text = text.replace(/^```(?:json)?\s*/i, "");
    text = text.replace(/```\s*$/, "");
    text = text.trim();
  }

  // Find JSON object boundaries if surrounded by conversational filler
  const firstBrace = text.indexOf("{");
  const lastBrace = text.lastIndexOf("}");
  if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
    text = text.slice(firstBrace, lastBrace + 1);
  }

  try {
    const parsed = JSON.parse(text) as { allow?: boolean; reason?: string };
    if (typeof parsed.allow !== "boolean") {
      throw new Error("no boolean allow field");
    }
    const allow = parsed.allow;
    const reason = typeof parsed.reason === "string" && parsed.reason.length > 0
      ? parsed.reason
      : (allow ? "Allowed by security classifier" : "Denied by security classifier");
    return { allow, reason };
  } catch {
    return new UnparseableReply({ allow: false, reason: `Failed to parse classifier JSON output (${text.slice(0, 100)})` });
  }
}

/** The verdict in a reply; one that does not parse fails closed (deny). */
export function parseClassificationResponse(rawContent: string): { allow: boolean; reason: string } {
  const v = parseVerdict(rawContent);
  return v instanceof UnparseableReply ? v.verdict : v;
}

/**
 * Anything that can turn a command (plus optional file context) into a verdict.
 * LlmClient is the production implementation; tests inject a scripted one.
 */
export interface Classifier {
  classify(command: string, fileContext?: FileContext, sessionId?: string, facts?: GateFacts): Promise<ClassificationResult>;
}

/**
 * Marks a completion as the gate's own, not the agent's. The gate runs on a
 * different model, on a different budget, answering a question the agent never
 * asked and never sees the answer to, so folding its spend into the agent's
 * session would overstate what that session cost. Suffixing instead keeps both
 * questions answerable: the rows still group under the session by prefix, and
 * still separate from it exactly.
 */
export const SESSION_MARKER = "auto-classifier";

/** `ses_abc` -> `ses_abc:auto-classifier`. */
export function markSession(sessionId: string): string {
  return `${sessionId}:${SESSION_MARKER}`;
}

/**
 * Request fields that stop a reasoning model spending the completion budget on
 * a hidden chain-of-thought. A classifier reply is one short JSON object; a
 * model that reasons first returns it truncated, or returns nothing, under any
 * sane max_tokens. Keyed by the route prefix a routing gateway reads (the text
 * before the first `/` of the model id).
 */
export const ROUTE_REQUEST_DEFAULTS: Record<string, Record<string, unknown>> = {
  openrouter: { reasoning: { enabled: false } },
  deepseek: { thinking: { type: "disabled" } },
  "ollama-cloud": { reasoning_effort: "none" },
};

/** Endpoints spoken to directly, whose model ids carry no route prefix. */
const HOST_ROUTES: Array<[RegExp, string]> = [
  [/(^|\.)openrouter\.ai$/i, "openrouter"],
  [/(^|\.)deepseek\.com$/i, "deepseek"],
  [/(^|\.)ollama\.com$/i, "ollama-cloud"],
];

export function routeFor(model: string, baseUrl?: string): string {
  if (baseUrl) {
    try {
      const host = new URL(baseUrl).hostname;
      const hit = HOST_ROUTES.find(([re]) => re.test(host));
      if (hit) return hit[1];
    } catch {
      // not a URL; fall through to the prefix
    }
  }
  return model.includes("/") ? model.slice(0, model.indexOf("/")) : "";
}

export function requestExtras(model: string, extraBody?: Record<string, unknown>, baseUrl?: string): Record<string, unknown> {
  const route = routeFor(model, baseUrl);
  const merged: Record<string, unknown> = { ...(ROUTE_REQUEST_DEFAULTS[route] ?? {}), ...(extraBody ?? {}) };
  for (const k of Object.keys(merged)) if (merged[k] === null) delete merged[k];
  return merged;
}

export type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body: string; signal: AbortSignal }) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
  json(): Promise<unknown>;
}>;

export class LlmClient implements Classifier {
  private config: LlmConfig;
  private fetchImpl: FetchLike;

  constructor(config: LlmConfig, fetchImpl: FetchLike = (url, init) => fetch(url, init)) {
    this.config = config;
    this.fetchImpl = fetchImpl;
  }

  private async executeRequest(
    model: string,
    prompt: string,
    systemPrompt: string,
    timeoutMs: number,
    sessionId?: string,
    usage?: Usage
  ): Promise<string> {
    const url = `${this.config.baseUrl.replace(/\/+$/, "")}/chat/completions`;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    if (this.config.apiKey) {
      headers["Authorization"] = `Bearer ${this.config.apiKey}`;
    }

    // A gateway that attributes spend per session reads this; a plain
    // OpenAI-compatible endpoint ignores an unknown header, so sending it
    // always is safe and needs no configuration.
    if (sessionId) {
      headers["X-Session-Id"] = markSession(sessionId);
    }

    const payload = {
      model,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: prompt },
      ],
      temperature: 0.0,
      max_tokens: this.config.maxTokens ?? 120,
      stream: false,
      ...requestExtras(model, this.config.extraBody, this.config.baseUrl),
    };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await this.fetchImpl(url, {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => "");
        throw new Error(`LLM HTTP ${response.status}: ${errorText.slice(0, 200)}`);
      }

      const json = (await response.json()) as {
        choices?: Array<{ message?: { content?: string } }>;
        usage?: { prompt_tokens?: number; completion_tokens?: number };
      };
      if (usage) {
        usage.calls++;
        usage.input_tokens += json.usage?.prompt_tokens ?? 0;
        usage.output_tokens += json.usage?.completion_tokens ?? 0;
      }

      const content = json.choices?.[0]?.message?.content;
      if (!content) {
        throw new Error("Empty completion returned from LLM provider");
      }

      return content;
    } finally {
      clearTimeout(timer);
    }
  }

  async classify(command: string, fileContext?: FileContext, sessionId?: string, facts?: GateFacts): Promise<ClassificationResult> {
    const systemPrompt = buildSystemPrompt(this.config.instructionsAppend, this.config.sanctionedRemotes, this.config.protectedBranches);
    const userPrompt = buildUserPrompt(command, fileContext, facts);
    const timeout = this.config.timeoutMs || 15000;
    const total = this.config.totalTimeoutMs || 18000;
    const deadline = Date.now() + total;
    // Each request gets its own timeout or what is left of the chain's
    // deadline, whichever is shorter; zero means the deadline has passed.
    const budget = () => Math.max(0, Math.min(timeout, deadline - Date.now()));
    let outOfTime = false;
    const usage: Usage = { input_tokens: 0, output_tokens: 0, calls: 0 };

    // 0. Optional cheap first pass. An allow from it is final; a deny, an
    // unparseable reply, or an error hands the same prompt to the primary model.
    if (this.config.triageModel && this.config.triageModel !== this.config.model) {
      try {
        const triageRaw = await this.executeRequest(this.config.triageModel, userPrompt, systemPrompt, budget(), sessionId, usage);
        const triage = parseClassificationResponse(triageRaw);
        if (triage.allow) {
          return { allow: true, reason: triage.reason, source: "triage", usage };
        }
      } catch (triageErr) {
        log(`triage model (${this.config.triageModel}) failed, asking primary: ${(triageErr as Error).message}`);
      }
    }

    // 1. The primary model, then the fallback chain (fallbackModel, then
    // fallbackModels), skipping the primary and any repeat. The first reply
    // that parses wins. A link that fails -- unreachable, erroring, or
    // answering with something that is not a verdict -- is logged and the next
    // is tried.
    let firstErr: Error | undefined;
    let unparseable: UnparseableReply | undefined;
    const chain: Array<[string, ClassificationResult["source"]]> = [
      [this.config.model, "llm"],
      ...this.fallbackChain().map((m): [string, ClassificationResult["source"]] => [m, "fallback"]),
    ];
    for (const [model, source] of chain) {
      const left = budget();
      if (left === 0) {
        outOfTime = true;
        log(`model chain stopped before ${model}: llm.totalTimeoutMs (${total} ms) has passed`);
        break;
      }
      try {
        if (source === "fallback") log(`retrying with fallback model (${model})`);
        const raw = await this.executeRequest(model, userPrompt, systemPrompt, left, sessionId, usage);
        const decision = parseVerdict(raw);
        if (decision instanceof UnparseableReply) throw decision;
        return { allow: decision.allow, reason: decision.reason, source, usage };
      } catch (err) {
        const e = err as Error;
        firstErr ??= e;
        if (e instanceof UnparseableReply) unparseable = e;
        log(source === "llm" ? `primary model (${model}) failed: ${e.message}` : `fallback model (${model}) also failed: ${e.message}`);
      }
    }

    // The whole chain is exhausted; fail closed. A model that answered, only
    // not parseably, gave a verdict of sorts: that deny is reused on a retry
    // like any other, so re-asking cannot re-roll it into an allow. Only a
    // chain that never got an answer at all is an outage (source "error"),
    // whose retry asks again.
    if (unparseable) {
      return { ...unparseable.verdict, source: "llm", usage };
    }
    if (outOfTime || (firstErr && Date.now() >= deadline)) {
      return {
        allow: false,
        reason: `LLM classification unreachable: no model answered within llm.totalTimeoutMs (${total} ms)${firstErr ? `; first failure: ${firstErr.message}` : ""}`,
        source: "error",
        usage,
      };
    }
    return {
      allow: false,
      reason: `LLM classification unreachable: ${firstErr?.message ?? "no model configured"}`,
      source: "error",
      usage,
    };
  }

  /** `fallbackModel` first, then `fallbackModels` in order, minus the primary model and any duplicate. */
  private fallbackChain(): string[] {
    const candidates = [this.config.fallbackModel, ...(this.config.fallbackModels ?? [])];
    const seen = new Set<string>();
    const chain: string[] = [];
    for (const m of candidates) {
      if (!m || m === this.config.model || seen.has(m)) continue;
      seen.add(m);
      chain.push(m);
    }
    return chain;
  }
}
