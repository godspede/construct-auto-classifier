import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { AutoClassifier } from "../index.js";
import { log } from "../log.js";
import { startAcceptWatcher, type AcceptTarget } from "./agy-accept.js";
import { judgeFileWrite } from "../rules/file-write.js";
import type { AgyPreToolUseInput, AgyPreToolUseOutput } from "../types.js";

/** One process as the auto-approve walk sees it. */
export interface ProcessEntry {
  /** argv, or on Windows the command line split the way a shell would. */
  args: string[];
  ppid: number;
}

/**
 * Looks up one process. Returns null when that process is gone or cannot be
 * read (which ends the walk), and throws when the table itself cannot be read
 * at all.
 */
export type ProcessReader = (pid: number) => ProcessEntry | null;

/** Linux: argv and parent from /proc. */
export function procReader(pid: number): ProcessEntry | null {
  try {
    const args = fs.readFileSync(path.join("/proc", String(pid), "cmdline"), "utf-8").split("\0");
    const stat = fs.readFileSync(path.join("/proc", String(pid), "stat"), "utf-8");
    const ppid = parseInt(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1] ?? "0", 10);
    return { args, ppid };
  } catch {
    return null;
  }
}

/** Split a Windows command line into arguments, honouring double quotes. */
export function splitCommandLine(line: string): string[] {
  return (line.match(/"[^"]*"|\S+/g) ?? []).map((a) => a.replace(/^"|"$/g, ""));
}

/**
 * Windows: one snapshot of every process's command line and parent, taken
 * the first time a pid is asked for. Windows has no /proc, and a process's
 * command line is only readable through WMI/CIM, so this asks PowerShell
 * once, hidden. It throws when the snapshot fails, so the caller can refuse
 * to guess.
 */
export function windowsProcessReader(
  snapshot: () => string = () =>
    execFileSync(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,CommandLine | ConvertTo-Json -Compress",
      ],
      { encoding: "utf-8", timeout: 10000, windowsHide: true, maxBuffer: 64 * 1024 * 1024 }
    )
): ProcessReader {
  let table: Map<number, ProcessEntry> | null = null;
  return (pid) => {
    if (!table) {
      const rows = JSON.parse(snapshot()) as Array<{ ProcessId: number; ParentProcessId: number; CommandLine: string | null }>;
      table = new Map(
        (Array.isArray(rows) ? rows : [rows]).map((r) => [
          r.ProcessId,
          { args: splitCommandLine(r.CommandLine ?? ""), ppid: r.ParentProcessId },
        ])
      );
    }
    return table.get(pid) ?? null;
  };
}

function defaultProcessReader(): ProcessReader {
  return process.platform === "win32" ? windowsProcessReader() : procReader;
}

/**
 * Why agy would approve a hook's `ask`/`force_ask` by itself, or null when a
 * prompt would reach the operator. Both of agy's auto-approve switches answer
 * a hook's escalation too, so under either one an escalation is only safe as
 * a denial:
 *  - `--dangerously-skip-permissions` on the agy process this hook runs under,
 *    found by walking up the process tree (/proc on Linux, one CIM snapshot on
 *    Windows). Only the flag's presence is checked; the arguments are never
 *    logged or returned. If the process table cannot be read at all, that is
 *    reported as a reason too: an escalation the gate cannot prove will reach
 *    the operator is refused rather than risked.
 *  - `"toolPermission": "always-proceed"` in agy's settings.json. A missing
 *    key is agy's default, which asks.
 */
export function detectAgyAutoApprove(
  settingsPath = path.join(process.env.HOME || os.homedir(), ".gemini", "antigravity-cli", "settings.json"),
  startPid = process.ppid,
  readProcess: ProcessReader = defaultProcessReader()
): string | null {
  let pid = startPid;
  for (let depth = 0; depth < 8 && pid > 1; depth++) {
    let entry: ProcessEntry | null;
    try {
      entry = readProcess(pid);
    } catch (err) {
      log(`agy: could not read the process table: ${(err as Error).message}`);
      return "the gate could not check whether agy was started with --dangerously-skip-permissions";
    }
    if (!entry) break;
    // Only agy's own flag counts; any other ancestor (another harness this
    // shell runs under, say) may carry a flag of the same name.
    if (/^agy(\.exe)?$/i.test(path.basename((entry.args[0] ?? "").replace(/\\/g, "/")))) {
      if (entry.args.includes("--dangerously-skip-permissions")) {
        return "agy was started with --dangerously-skip-permissions";
      }
      break;
    }
    pid = entry.ppid;
  }
  try {
    const settings = JSON.parse(fs.readFileSync(settingsPath, "utf-8"));
    if (settings?.toolPermission === "always-proceed") {
      return `agy's toolPermission is "always-proceed" (${settingsPath})`;
    }
  } catch {
    // No settings file, or one we cannot read: agy's default asks.
  }
  return null;
}

/**
 * The Antigravity PreToolUse hook, as a pure function: raw stdin text in, the
 * JSON object to print on stdout out. `runAgyHook` is the thin process wrapper.
 * Every prompt it would return passes through `autoApprove` first.
 */
export async function handleAgyInput(
  rawInput: string,
  classifier: AutoClassifier,
  autoApprove: () => string | null = detectAgyAutoApprove,
  onAllow: (target: string | AcceptTarget) => boolean = (target) => watchForPrompt(classifier, target)
): Promise<AgyPreToolUseOutput> {
  const out = await decide(rawInput, classifier, onAllow);
  if (out.decision !== "ask" && out.decision !== "force_ask") {
    return out;
  }
  const why = autoApprove();
  if (!why) {
    return out;
  }
  // agy would answer this prompt itself, turning an escalation into an
  // approval. Block it, and say why.
  log(`agy: escalation blocked, not prompted: ${why}`);
  return {
    decision: "deny",
    reason:
      `${out.reason ?? "The safety classifier needs the operator's decision."}\n` +
      `Blocked: this needs the operator's approval, and ${why}, so a prompt here would approve it without them. ` +
      `Stop, and ask the operator to decide on this.`,
  };
}

/**
 * With `agy.autoAcceptInTmux`, start the watcher that accepts agy's prompt for
 * this allowed command (agy-accept.ts). Only inside tmux, where the pane agy
 * runs in is known.
 */
function watchForPrompt(classifier: AutoClassifier, target: string | AcceptTarget): boolean {
  const pane = process.env.TMUX_PANE;
  if (!pane || !process.env.TMUX || !classifier.getConfig().agy?.autoAcceptInTmux) {
    return false;
  }
  startAcceptWatcher(pane, target);
  return true;
}

/** agy's tools that write a file (TargetFile in their args). */
export const FILE_TOOLS = new Set(["write_to_file", "replace_file_content", "multi_replace_file_content"]);

async function decide(
  rawInput: string,
  classifier: AutoClassifier,
  onAllow: (target: string | AcceptTarget) => boolean
): Promise<AgyPreToolUseOutput> {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    // Empty input, allow
    return { decision: "allow" };
  }

  let input: AgyPreToolUseInput;
  try {
    input = JSON.parse(trimmed) as AgyPreToolUseInput;
  } catch (err) {
    // Malformed input from harness, log to stderr and fail-safe to force_ask
    log(`agy: JSON parse error on stdin: ${(err as Error).message}`);
    return {
      decision: "force_ask",
      reason: "Malformed PreToolUse JSON payload received by hook",
    };
  }

  const toolName = input.toolCall?.name || "";
  const command = input.toolCall?.args?.CommandLine || "";
  const sessionId = input.conversationId || "agy-session";

  // agy's file-writing tools carry a target path, not a command: judged by
  // where the write lands (rules/file-write.ts), no model involved.
  if (FILE_TOOLS.has(toolName)) {
    const target = typeof input.toolCall?.args?.TargetFile === "string" ? input.toolCall.args.TargetFile : "";
    const workspaces = Array.isArray(input.workspacePaths) ? input.workspacePaths.filter((w): w is string => typeof w === "string") : [];
    const verdict = judgeFileWrite(target, workspaces);
    log(`agy: ${verdict.decision} ${toolName} ${target}`);
    if (verdict.decision === "deny") return { decision: "deny", reason: verdict.reason };
    if (verdict.decision === "escalate") return { decision: "force_ask", reason: `⚠️ SAFETY ESCALATION: ${verdict.reason}` };
    onAllow({ kind: "file", path: target });
    return { decision: "allow" };
  }

  // Other tools are not this hook's; allow them immediately.
  if (toolName !== "run_command" || !command.trim()) {
    return { decision: "allow" };
  }

  try {
    const cwd = typeof input.toolCall?.args?.Cwd === "string" && input.toolCall.args.Cwd ? input.toolCall.args.Cwd : undefined;
    const outcome = await classifier.evaluate(command, sessionId, undefined, { cwd });
    if (outcome.decision === "allow" && onAllow(command)) {
      // No reason: the watcher reads a reason on agy's prompt as an
      // escalation, and leaves it for the operator.
      return { decision: "allow" };
    }
    return { decision: outcome.decision, reason: outcome.reason };
  } catch (err) {
    log(`agy: evaluation error: ${(err as Error).message}`);
    // On unexpected error, fall back to interactive prompt rather than silent allow
    return {
      decision: "force_ask",
      reason: `Classifier encountered internal error: ${(err as Error).message}`,
    };
  }
}

export async function runAgyHook(classifier?: AutoClassifier): Promise<void> {
  const instance = classifier || new AutoClassifier();

  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  const rawInput = Buffer.concat(chunks).toString("utf-8");

  const output = await handleAgyInput(rawInput, instance);
  process.stdout.write(JSON.stringify(output) + "\n");
}
