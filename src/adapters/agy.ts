import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { AutoClassifier } from "../index.js";
import { log } from "../log.js";
import { writeTelemetry } from "../telemetry.js";
import { startAcceptWatcher, startEscalationWatcher, consumeLastTimeout, timeoutMessage, type AcceptTarget } from "./agy-accept.js";
import { judgeFileWrite, type FileWriteVerdict } from "../rules/file-write.js";
import { detectInjectionAttempt } from "../rules/injection-detection.js";
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

/** Split a Windows command line into arguments, honoring double quotes. */
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
 * Why the running agy with this pid is answering tool confirmations by itself,
 * or null when nothing says so.
 */
export type LiveModeReader = (agyPid: number) => string | null;

const LOG_PID = /Starting language server process with pid (\d+)\b/;
const CONFIRMATION = /(Always-proceed: auto-approving|Surfacing) tool confirmation/g;

/**
 * Reads agy's own log for the running process. settings.json is only what the
 * next agy will start with: a toolPermission changed in /settings lives on in
 * the running process after the file is rewritten (an installer resetting it
 * to request-review, say), and that process approves a `force_ask` with no
 * prompt at all. Its log says which way it answered the last confirmation it
 * was asked: "Always-proceed: auto-approving tool confirmation" or
 * "Surfacing tool confirmation". The file for a process is the one whose
 * first line names its pid.
 */
export function agyLogLiveMode(
  logDir = path.join(process.env.HOME || os.homedir(), ".gemini", "antigravity-cli", "log"),
  tailBytes = 1024 * 1024
): LiveModeReader {
  return (agyPid) => {
    let names: string[];
    try {
      names = fs.readdirSync(logDir).filter((n) => /^cli-.*\.log$/.test(n)).sort().reverse();
    } catch {
      return null;
    }
    for (const name of names.slice(0, 200)) {
      const file = path.join(logDir, name);
      let fd: number | undefined;
      try {
        fd = fs.openSync(file, "r");
        const head = Buffer.alloc(4096);
        const headLen = fs.readSync(fd, head, 0, head.length, 0);
        const pid = LOG_PID.exec(head.toString("utf-8", 0, headLen));
        if (!pid || Number(pid[1]) !== agyPid) continue;

        const size = fs.fstatSync(fd).size;
        const start = Math.max(0, size - tailBytes);
        const tail = Buffer.alloc(size - start);
        fs.readSync(fd, tail, 0, tail.length, start);
        const last = [...tail.toString("utf-8").matchAll(CONFIRMATION)].pop();
        return last?.[1] === "Surfacing" || !last
          ? null
          : `the running agy is approving tool confirmations by itself (always-proceed, whatever settings.json says now; ${file})`;
      } catch {
        continue;
      } finally {
        if (fd !== undefined) fs.closeSync(fd);
      }
    }
    return null;
  };
}

/** detectAgyAutoApprove's answer when it cannot tell: never treated as the operator's choice. */
export const CANNOT_CHECK = "the gate could not check whether agy was started with --dangerously-skip-permissions";

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
 *  - always-proceed in the running agy, read from its own log
 *    (`agyLogLiveMode`), which settings.json stops describing once it is
 *    rewritten under a running agy.
 *  - `"toolPermission": "always-proceed"` in agy's settings.json. A missing
 *    key is agy's default, which asks.
 */
export function detectAgyAutoApprove(
  settingsPath = path.join(process.env.HOME || os.homedir(), ".gemini", "antigravity-cli", "settings.json"),
  startPid = process.ppid,
  readProcess: ProcessReader = defaultProcessReader(),
  readLiveMode: LiveModeReader = agyLogLiveMode()
): string | null {
  let pid = startPid;
  for (let depth = 0; depth < 8 && pid > 1; depth++) {
    let entry: ProcessEntry | null;
    try {
      entry = readProcess(pid);
    } catch (err) {
      log(`agy: could not read the process table: ${(err as Error).message}`);
      return CANNOT_CHECK;
    }
    if (!entry) break;
    // Only agy's own flag counts; any other ancestor (another harness this
    // shell runs under, say) may carry a flag of the same name.
    if (/^agy(\.exe)?$/i.test(path.basename((entry.args[0] ?? "").replace(/\\/g, "/")))) {
      if (entry.args.includes("--dangerously-skip-permissions")) {
        return "agy was started with --dangerously-skip-permissions";
      }
      const live = readLiveMode(pid);
      if (live) return live;
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
  onAllow: (target: string | AcceptTarget) => boolean = (target) => watchForPrompt(classifier, target),
  onEscalate: (target: AcceptTarget, sessionId?: string) => boolean = (target, sid) => watchForEscalation(classifier, target, sid)
): Promise<AgyPreToolUseOutput> {
  // The timeout watcher starts only once the prompt is known to reach the
  // operator: a blocked escalation has no prompt to watch.
  let escalation: [AcceptTarget, string | undefined] | null = null;
  let byGate = false;
  const out = await decide(rawInput, classifier, onAllow, (target, sid, gateRaised) => {
    escalation = [target, sid];
    byGate = gateRaised === true;
    return true;
  });
  if (out.decision !== "ask" && out.decision !== "force_ask") {
    return out;
  }
  const esc = escalation as [AcceptTarget, string | undefined] | null;
  const config = classifier.getConfig();
  // Nobody is at the keyboard, so no escalation can be answered.
  if (config.policy.headless) {
    log(`agy: escalation blocked, headless`);
    if (esc) recordUnprompted(classifier, esc, byGate ? "gate-kept" : "no-prompt", `refused, headless: ${out.reason ?? ""}`);
    return {
      decision: "deny",
      reason:
        `${out.reason ?? "The safety classifier needs the user's decision."}\n` +
        `Blocked: this session is headless, so nobody can answer a prompt here. Stop, and report to the user that this needs their decision.`,
    };
  }
  const why = autoApprove();
  if (!why) {
    if (esc) onEscalate(...esc);
    return out;
  }
  // agy will answer this prompt itself. For an escalation the model raised
  // that is the operator's standing choice (always-proceed, or the flag)
  // unless `agy.alwaysProceedEscalations` is "stop": it runs, and says so in
  // the log and telemetry. A gate failure, or a process table the gate could
  // not read, is never taken as that choice, and neither is an escalation the
  // gate raised (a rule's refusal, an escalated file write, a script cut
  // short, or a model that could not be reached): it exists only for a
  // person to decide.
  if (byGate && esc) {
    log(`agy: gate-raised escalation refused, no prompt: ${why}`);
    recordUnprompted(classifier, esc, "gate-kept", `refused, no prompt: ${why}. ${out.reason ?? ""}`);
    return {
      decision: "deny",
      reason:
        `${out.reason ?? "The safety classifier needs the user's decision."}\n` +
        `Blocked: the gate itself raised this for the user to decide, not a model's judgement (a rule's refusal, an escalated file write, a script cut short before the model saw it whole, or a model that could not be reached), but ${why}, so a prompt here would approve it without them. ` +
        `Stop, and ask the user to decide on this.`,
    };
  }
  if (esc && why !== CANNOT_CHECK && (config.agy?.alwaysProceedEscalations ?? "run") === "run") {
    const [target, sid] = esc;
    const what = target.kind === "file" ? `file ${target.path}` : target.command;
    log(`agy: escalation ran unattended (always-proceed): ${why}: "${what.slice(0, 120).replace(/\n/g, " ")}"`);
    recordUnprompted(classifier, esc, "always-proceed", `escalation approved by agy itself, no prompt: ${why}. ${out.reason ?? ""}`, "allow");
    return out;
  }
  // Block it, and say why.
  log(`agy: escalation blocked, not prompted: ${why}`);
  if (esc) recordUnprompted(classifier, esc, "no-prompt", `refused, no prompt: ${why}. ${out.reason ?? ""}`);
  return {
    decision: "deny",
    reason:
      `${out.reason ?? "The safety classifier needs the user's decision."}\n` +
      `Blocked: this needs the user's approval, and ${why}, so a prompt here would approve it without them. ` +
      `Stop, and ask the user to decide on this.`,
  };
}

/**
 * The telemetry row for what became of an escalation that never reached a
 * prompt: run by agy itself (`always-proceed`), or refused instead (one the
 * gate raised, `gate-kept`; any other, `no-prompt`). The classifier's own
 * row for the call still says `force_ask`.
 */
function recordUnprompted(
  classifier: AutoClassifier,
  [target, sid]: [AcceptTarget, string | undefined],
  source: "always-proceed" | "gate-kept" | "no-prompt",
  reason: string,
  decision: "allow" | "deny" = "deny"
): void {
  writeTelemetry(classifier.getConfig().telemetry, {
    id: "",
    session: sid ?? "",
    command: target.kind === "command" ? target.command.trim() : "",
    file_path: target.kind === "file" ? target.path : null,
    file_snippet: null,
    decision,
    source,
    reason: reason.trim(),
    latency_ms: 0,
    model: null,
    injection_attempt: false,
    injection_pattern: null,
    cwd: null,
  });
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

/**
 * Start the watcher that auto-denies agy's prompt after the escalation timeout
 * if the operator does not respond.
 */
function watchForEscalation(classifier: AutoClassifier, target: AcceptTarget, sessionId?: string): boolean {
  const pane = process.env.TMUX_PANE;
  if (!pane || !process.env.TMUX) {
    return false;
  }
  const timeoutMinutes = classifier.getConfig().policy.escalationTimeoutMinutes ?? 5;
  startEscalationWatcher(pane, target, timeoutMinutes, sessionId);
  return true;
}

/** The stage a file-write verdict came from, as telemetry names it. */
function fileVerdictSource(verdict: FileWriteVerdict): string {
  if (verdict.decision === "allow") return "workspace-allow";
  if (verdict.decision === "deny") return "protected-deny";
  // judgeFileWrite escalates for two reasons: the write lands outside every
  // workspace (or names no file), or it lands in a sensitive place inside one.
  return /outside the session's workspace|named no target file/.test(verdict.reason) ? "outside-escalate" : "sensitive-escalate";
}

/** agy's tools that write a file (TargetFile in their args). */
export const FILE_TOOLS = new Set(["write_to_file", "replace_file_content", "multi_replace_file_content"]);

async function decide(
  rawInput: string,
  classifier: AutoClassifier,
  onAllow: (target: string | AcceptTarget) => boolean,
  onEscalate: (target: AcceptTarget, sessionId?: string, byGate?: boolean) => boolean
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
    const started = Date.now();
    const verdict = judgeFileWrite(target, workspaces);
    log(`agy: ${verdict.decision} ${toolName} ${target}`);
    const label = `${toolName} ${target}`;
    const injectionPattern = detectInjectionAttempt(label);
    writeTelemetry(classifier.getConfig().telemetry, {
      id: "",
      session: sessionId,
      command: label,
      file_path: target || null,
      file_snippet: null,
      decision: verdict.decision === "escalate" ? "force_ask" : verdict.decision,
      source: fileVerdictSource(verdict),
      reason: verdict.decision === "allow" ? "write stays inside the session's workspace" : verdict.reason,
      latency_ms: Date.now() - started,
      model: null,
      injection_attempt: injectionPattern !== null,
      injection_pattern: injectionPattern,
      cwd: workspaces[0] ?? null,
      tool: toolName,
    });
    if (verdict.decision === "deny") return { decision: "deny", reason: verdict.reason };
    if (verdict.decision === "escalate") {
      // The gate raised this, not the model.
      onEscalate({ kind: "file", path: target }, sessionId, true);
      return { decision: "force_ask", reason: `⚠️ SAFETY ESCALATION: ${verdict.reason}` };
    }
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
    if (outcome.decision === "force_ask" || outcome.decision === "ask") {
      onEscalate({ kind: "command", command }, sessionId, outcome.gateRaised);
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

/**
 * Handle Antigravity's PreInvocation hook: if the previous action timed out
 * waiting for the operator, inject an explanation into the prompt.
 */
export function handleAgyPreInvocation(
  input: { conversationId?: string; [key: string]: unknown }
): { injectSteps: Array<{ ephemeralMessage: string }> } {
  const timeoutRecord = consumeLastTimeout(input.conversationId);
  if (timeoutRecord) {
    const msg = timeoutMessage(timeoutRecord.target, timeoutRecord.timeoutMinutes ?? 5);
    return {
      injectSteps: [
        {
          ephemeralMessage: msg,
        },
      ],
    };
  }
  return { injectSteps: [] };
}

export async function runAgyHook(classifier?: AutoClassifier): Promise<void> {
  const instance = classifier || new AutoClassifier();

  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  const rawInput = Buffer.concat(chunks).toString("utf-8");

  try {
    const trimmed = rawInput.trim();
    if (trimmed) {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === "object" && ("invocationNum" in parsed || !parsed.toolCall)) {
        const preInvOutput = handleAgyPreInvocation(parsed);
        process.stdout.write(JSON.stringify(preInvOutput) + "\n");
        return;
      }
    }
  } catch {}

  const output = await handleAgyInput(rawInput, instance);
  process.stdout.write(JSON.stringify(output) + "\n");
}
