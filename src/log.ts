import path from "node:path";
import { appendCapped } from "./capped-append.js";
import { gateConfigDir } from "./paths.js";

/**
 * A line-per-event log file, because a plugin's stderr goes wherever the host
 * harness sends it, which is usually nowhere anyone reads. Default path:
 * ~/.config/auto-classifier/auto-classifier.log. AUTO_CLASSIFIER_LOG overrides;
 * an empty string disables. Past `LOG_MAX_BYTES` the file moves to
 * `<log>.1`, replacing any older one.
 */
export function logPath(): string | null {
  const env = process.env.AUTO_CLASSIFIER_LOG;
  if (env !== undefined) return env === "" ? null : env;
  return path.join(gateConfigDir(), "auto-classifier.log");
}

/** 10 MB: the log carries one short line per event, so this is weeks of it. */
export const LOG_MAX_BYTES = 10 * 1024 * 1024;

export function log(message: string): void {
  const p = logPath();
  if (!p) return;
  try {
    appendCapped(p, `[auto-classifier][${new Date().toISOString()}] ${message}\n`, LOG_MAX_BYTES);
  } catch {
    // a log that cannot be written must never break a verdict
  }
}
