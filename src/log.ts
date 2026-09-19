import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/**
 * A line-per-event log file, because a plugin's stderr goes wherever the host
 * harness sends it, which is usually nowhere anyone reads. Default path:
 * ~/.config/auto-classifier/auto-classifier.log. AUTO_CLASSIFIER_LOG overrides;
 * an empty string disables.
 */
export function logPath(): string | null {
  const env = process.env.AUTO_CLASSIFIER_LOG;
  if (env !== undefined) return env === "" ? null : env;
  const configHome = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config");
  return path.join(configHome, "auto-classifier", "auto-classifier.log");
}

export function log(message: string): void {
  const p = logPath();
  if (!p) return;
  try {
    fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o700 });
    fs.appendFileSync(p, `[auto-classifier][${new Date().toISOString()}] ${message}\n`, { mode: 0o600 });
  } catch {
    // a log that cannot be written must never break a verdict
  }
}
