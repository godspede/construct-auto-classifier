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

/**
 * agy's prompt for a file-writing tool (write_to_file, replace_file_content):
 *
 *     ────────────────────────────
 *     D:\tmp\project\notes.txt  +1 -1
 *        1 -  old line
 *        1 +  new line
 *     Accept this file edit?            (or: Allow creation of this file?)
 *     > 1. Yes, accept this change      (or: > 1. Yes, allow creation)
 *
 * The file is the first line after the rule above the question, followed by
 * its +added/-removed counts.
 */
export interface FilePrompt {
  /** The file agy is asking about, as displayed. */
  path: string;
  /** "1. Yes, ..." is the highlighted option. */
  yesSelected: boolean;
  /** The prompt carries a hook reason: an escalation, which is the operator's. */
  hasReason: boolean;
}

const FILE_QUESTION = /^\s*(Allow creation of this file\?|Accept this file edit\?)\s*$/;
const FILE_YES_SELECTED = /^\s*>\s*1\.\s*Yes, (allow creation|accept this change)\s*$/;
const FILE_HEADER = /^\s*(\S.*?)\s{2,}\+\d+(\s+-\d+)?\s*$/;

/** The last file-write prompt on the screen, or null when none is showing. */
export function readFilePrompt(screen: string): FilePrompt | null {
  const lines = screen.split("\n");
  let question = -1;
  for (let i = lines.length - 1; i >= 0; i--) {
    if (FILE_QUESTION.test(lines[i]!)) {
      question = i;
      break;
    }
  }
  if (question < 0) return null;

  let rule = -1;
  for (let i = question - 1; i >= 0; i--) {
    if (RULE.test(lines[i]!)) {
      rule = i;
      break;
    }
  }
  // agy leaves a blank line between the rule and the file line.
  const headerLine = rule >= 0 ? lines.slice(rule + 1, question).find((l) => l.trim() !== "") ?? "" : "";
  const header = FILE_HEADER.exec(headerLine);
  if (!header) return null;

  // A hook reason sits above the rule, as it does for a command prompt, or
  // anywhere between the rule and the question.
  let hasReason = lines.slice(rule, question).some((l) => /^\s*Reason:/.test(l));
  for (let i = rule - 1; i >= 0 && i >= rule - 15; i--) {
    if (RULE.test(lines[i]!)) break;
    if (/^\s*Reason:/.test(lines[i]!)) hasReason = true;
  }

  const firstOption = lines.slice(question + 1).find((l) => l.trim() !== "") ?? "";
  return { path: header[1]!, yesSelected: FILE_YES_SELECTED.test(firstOption), hasReason };
}

/** Compared the way the filesystem would: separators unified, case-folded on Windows. */
const samePath = (a: string, b: string) => {
  const n = (p: string) => {
    const s = p.trim().replace(/\\/g, "/");
    return process.platform === "win32" ? s.toLowerCase() : s;
  };
  return n(a) !== "" && n(a) === n(b);
};

/** The file prompt is safe to accept for `allowedPath`: that file, option 1 highlighted, no hook reason. */
export function filePromptMatches(prompt: FilePrompt | null, allowedPath: string): boolean {
  return prompt !== null && prompt.yesSelected && !prompt.hasReason && samePath(prompt.path, allowedPath);
}

/** What the gate allowed, and so what the watcher may accept. */
export type AcceptTarget = { kind: "command"; command: string } | { kind: "file"; path: string };

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
  capture: (pane) => execFileSync("tmux", ["capture-pane", "-p", "-J", "-t", pane], { encoding: "utf-8", timeout: 2000, windowsHide: true }),
  pressEnter: (pane) => {
    execFileSync("tmux", ["send-keys", "-t", pane, "Enter"], { timeout: 2000, windowsHide: true });
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
  allowed: string | AcceptTarget,
  io: PaneIO = tmuxPane,
  windowMs = 5000,
  pollMs = 100
): Promise<AcceptResult> {
  const target: AcceptTarget = typeof allowed === "string" ? { kind: "command", command: allowed } : allowed;
  // [is the prompt on screen at all, is it the one the gate allowed]
  const look = (screen: string): [boolean, boolean] => {
    if (target.kind === "command") {
      const p = readPermissionPrompt(screen);
      return [p !== null, promptMatches(p, target.command)];
    }
    const p = readFilePrompt(screen);
    return [p !== null, filePromptMatches(p, target.path)];
  };
  let sawOther = false;
  try {
    for (let waited = 0; waited <= windowMs; waited += pollMs) {
      const [shown, matches] = look(io.capture(pane));
      if (matches) {
        if (!look(io.capture(pane))[1]) {
          return "mismatch";
        }
        io.pressEnter(pane);
        return "accepted";
      }
      if (shown) sawOther = true;
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
export function startAcceptWatcher(pane: string, allowed: string | AcceptTarget, cliPath = process.argv[1] ?? ""): void {
  const target: AcceptTarget = typeof allowed === "string" ? { kind: "command", command: allowed } : allowed;
  try {
    const child = spawn(process.execPath, [cliPath, "agy-accept", pane], {
      detached: true,
      stdio: ["pipe", "ignore", "ignore"],
      // On Windows a detached child has no console, so every console program
      // it runs (tmux, per poll) would get a fresh window that flashes open.
      windowsHide: true,
    });
    child.on("error", (err) => log(`agy-accept: could not start the watcher: ${err.message}`));
    child.stdin?.end(JSON.stringify(target));
    child.unref();
  } catch (err) {
    log(`agy-accept: could not start the watcher: ${(err as Error).message}`);
  }
}

/** The `agy-accept <pane>` subcommand: the detached watcher's body. */
export async function runAcceptWatcher(pane: string): Promise<void> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  const raw = Buffer.concat(chunks).toString("utf-8");
  let target: AcceptTarget;
  try {
    const parsed = JSON.parse(raw) as AcceptTarget;
    target = parsed.kind === "file" ? { kind: "file", path: String(parsed.path ?? "") } : { kind: "command", command: String(parsed.command ?? "") };
  } catch {
    target = { kind: "command", command: raw };
  }
  const result = await acceptWhenShown(pane, target);
  const what = target.kind === "file" ? `file ${target.path}` : target.command;
  log(`agy-accept: ${result} "${what.slice(0, 120).replace(/\n/g, " ")}"`);
}
