import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DecisionOutcome, FileContext, TelemetryConfig } from "./types.js";
export type { TelemetryConfig };

/**
 * One JSON line per decision: the corpus for promoting frequent benign
 * commands to fast-allow rules, for seeing what fell through to the model,
 * and for re-certifying a model against real traffic.
 */
export interface TelemetryRow {
  type: "classification";
  id: string;
  ts: string;
  session: string;
  command: string;
  file_path: string | null;
  file_snippet: string | null;
  decision: DecisionOutcome["decision"];
  /** Which stage decided: fast-allow, fast-deny, retry, landed, cache, triage, llm, fallback, error. */
  source: string;
  reason: string;
  latency_ms: number;
  model: string | null;
  /** Tokens the model calls behind this decision spent; null when no model was asked. */
  usage?: { input_tokens: number; output_tokens: number; calls: number } | null;
  /** Jev's raw answers for this decision, so thresholds can be re-scored without new calls. */
  jev?: { model?: string; answers: Record<string, unknown> } | null;
  /**
   * A deterministic tell (see rules/injection-detection.ts) fired on the
   * command or its file content. Independent of `decision`: the policy is
   * "allow, but tell you", so this never changed what ran -- it
   * only says whether the input tried to talk the classifier out of its own
   * rules.
   */
  injection_attempt: boolean;
  /** The matched pattern's own source, for triage; null when none fired. */
  injection_pattern: string | null;
  /**
   * The directory the command ran in (`EvaluateOptions.cwd`), or null when the
   * caller didn't pass one. Not consulted by anything in this package; it is
   * there so a reader of the log can tell which workspace a decision came
   * from and apply that workspace's own policy to it.
   */
  cwd: string | null;
}

export function telemetryPath(config: TelemetryConfig): string | null {
  if (!config.enabled) return null;
  if (config.path) return config.path;
  const configHome = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config");
  return path.join(configHome, "auto-classifier", "telemetry.jsonl");
}

const REDACT = [
  [/Bearer\s+[A-Za-z0-9_\-.]{15,}/gi, "Bearer [REDACTED]"],
  [/([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD)\s*=\s*)(['"]?)[^\s'"]{8,}\2/gi, "$1$2[REDACTED]$2"],
] as const;

export function redactForTelemetry(text: string): string {
  let out = text;
  for (const [re, rep] of REDACT) out = out.replace(re, rep);
  return out;
}

export function writeTelemetry(config: TelemetryConfig, row: Omit<TelemetryRow, "type" | "ts">): void {
  const p = telemetryPath(config);
  if (!p) return;
  const full: TelemetryRow = {
    type: "classification",
    ts: new Date().toISOString(),
    ...row,
    command: redactForTelemetry(row.command).slice(0, 2000),
    reason: redactForTelemetry(row.reason).slice(0, 500),
    file_snippet: row.file_snippet ? redactForTelemetry(row.file_snippet).slice(0, 400) : null,
  };
  try {
    fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o700 });
    fs.appendFileSync(p, JSON.stringify(full) + "\n", { mode: 0o600 });
  } catch {
    // telemetry that cannot be written must never break a verdict
  }
}

export function snippetOf(fileContext?: FileContext): string | null {
  if (!fileContext?.content) return null;
  return fileContext.content.slice(0, 400);
}
