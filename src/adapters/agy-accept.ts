import { execFileSync, spawn } from "node:child_process";
import { log } from "../log.js";

/**
 * Auto-accepting agy's permission prompt for a command the gate allowed.
 *
 * Under `toolPermission: "request-review"` agy asks before every command, even
 * one a hook allowed, while a hook's `force_ask` does reach the operator. So a
 * hook that allows a command starts a watcher on its own tmux pane: when agy's
 * prompt shows exactly that command, the watcher presses Enter on
 * "1. Yes, run command". Everything else is left for the operator.
 *
 * Every failure is a prompt the operator answers: no watcher unless the gate
 * computed an allow, and a watcher that cannot read the pane, sees another
 * command, a moved selection, an escalation, or nothing within its window
 * sends no key at all.
 */

export interface PermissionPrompt {
  /** The command agy is asking about, as displayed. */
  command: string;
  /** "1. Yes, run command" is the highlighted option. */
  yesSelected: boolean;
  /** The prompt carries a hook reason: an escalation, which is the operator's. */
  hasReason: boolean;
}

const REQUEST = /^\s*Requesting permission for:\s*$/;
const QUESTION = /^\s*Run this command\?\s*$/;
const YES_SELECTED = /^\s*>\s*1\.\s*Yes, run command\s*$/;
const RULE = /^\s*[─━-]{8,}\s*$/;

/** The last permission prompt on the screen, or null when none is showing. */
export function readPermissionPrompt(screen: string): PermissionPrompt | null {
  const lines = screen.split("\n");
  let start = -1;
  for (let i = lines.length - 1; i >= 0; i--) {
    if (REQUEST.test(lines[i]!)) {
      start = i;
      break;
    }
  }
  if (start < 0) return null;

  let question = -1;
  for (let i = start + 1; i < lines.length; i++) {
    if (QUESTION.test(lines[i]!)) {
      question = i;
      break;
    }
  }
  if (question < 0) return null;

  const command = lines.slice(start + 1, question).map((l) => l.trim()).filter(Boolean).join(" ");
  const firstOption = lines.slice(question + 1).find((l) => l.trim() !== "") ?? "";

  let hasReason = false;
  for (let i = start - 1; i >= 0 && i >= start - 15; i--) {
    if (RULE.test(lines[i]!)) break;
    if (/^\s*Reason:/.test(lines[i]!)) hasReason = true;
  }

  return { command, yesSelected: YES_SELECTED.test(firstOption), hasReason };
}

const squash = (s: string) => s.replace(/\s+/g, "");

/**
 * The prompt is safe to accept for `allowed`: the same command (compared
 * without whitespace, since the screen wraps and indents it), option 1 still
 * highlighted, and no hook reason on it.
 */
export function promptMatches(prompt: PermissionPrompt | null, allowed: string): boolean {
  return (
    prompt !== null &&
    prompt.yesSelected &&
    !prompt.hasReason &&
    squash(allowed) !== "" &&
    squash(prompt.command) === squash(allowed)
  );
}

export interface PaneIO {
  capture(pane: string): string;
  pressEnter(pane: string): void;
  sleep(ms: number): Promise<void>;
}

export const tmuxPane: PaneIO = {
  // -J joins lines the terminal wrapped, so a long command reads as one.
  capture: (pane) => execFileSync("tmux", ["capture-pane", "-p", "-J", "-t", pane], { encoding: "utf-8", timeout: 2000 }),
  pressEnter: (pane) => {
    execFileSync("tmux", ["send-keys", "-t", pane, "Enter"], { timeout: 2000 });
  },
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
};

export type AcceptResult = "accepted" | "not-shown" | "mismatch" | "error";

/**
 * Watch `pane` for up to `windowMs` and accept agy's prompt for `allowed`.
 * The screen is read again immediately before the key is sent.
 */
export async function acceptWhenShown(
  pane: string,
  allowed: string,
  io: PaneIO = tmuxPane,
  windowMs = 5000,
  pollMs = 100
): Promise<AcceptResult> {
  let sawOther = false;
  try {
    for (let waited = 0; waited <= windowMs; waited += pollMs) {
      const prompt = readPermissionPrompt(io.capture(pane));
      if (promptMatches(prompt, allowed)) {
        if (!promptMatches(readPermissionPrompt(io.capture(pane)), allowed)) {
          return "mismatch";
        }
        io.pressEnter(pane);
        return "accepted";
      }
      if (prompt) sawOther = true;
      await io.sleep(pollMs);
    }
  } catch (err) {
    log(`agy-accept: ${(err as Error).message}`);
    return "error";
  }
  return sawOther ? "mismatch" : "not-shown";
}

/**
 * Start the watcher detached, so the hook can return and agy can show its
 * prompt. The command goes over stdin, never argv, where any process could
 * read it.
 */
export function startAcceptWatcher(pane: string, command: string, cliPath = process.argv[1] ?? ""): void {
  try {
    const child = spawn(process.execPath, [cliPath, "agy-accept", pane], {
      detached: true,
      stdio: ["pipe", "ignore", "ignore"],
    });
    child.on("error", (err) => log(`agy-accept: could not start the watcher: ${err.message}`));
    child.stdin?.end(command);
    child.unref();
  } catch (err) {
    log(`agy-accept: could not start the watcher: ${(err as Error).message}`);
  }
}

/** The `agy-accept <pane>` subcommand: the detached watcher's body. */
export async function runAcceptWatcher(pane: string): Promise<void> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  const command = Buffer.concat(chunks).toString("utf-8");
  const result = await acceptWhenShown(pane, command);
  log(`agy-accept: ${result} "${command.slice(0, 120).replace(/\n/g, " ")}"`);
}
