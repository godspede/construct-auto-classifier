import os from "node:os";
import path from "node:path";

/**
 * The running user's home, read when it's needed. Bun caches os.homedir() at
 * startup, so a later HOME change (a test isolating itself) would otherwise be
 * ignored.
 */
export function homeDir(): string {
  return process.env.HOME || os.homedir();
}

/**
 * The one directory the gate keeps its files in: its config and overlay, and
 * by default its log, telemetry and escalation-timeout records. Every reader
 * resolves it here, so self-protection guards the directory the gate actually
 * uses. It is `~/.config/auto-classifier` on every platform, whatever
 * `XDG_CONFIG_HOME` says; the variables that move single files
 * (`AUTO_CLASSIFIER_CONFIG`, `AUTO_CLASSIFIER_LOG`, ...) are the way to move them.
 */
export function gateConfigDir(): string {
  return path.join(homeDir(), ".config", "auto-classifier");
}
