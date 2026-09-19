import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { AutoClassifier } from "../index.js";
import { log } from "../log.js";
import type { AgyPreToolUseInput, AgyPreToolUseOutput } from "../types.js";

/**
 * Why agy would approve a hook's `ask`/`force_ask` by itself, or null when a
 * prompt would reach the operator. Both of agy's auto-approve switches answer
 * a hook's escalation too, so under either one an escalation is only safe as
 * a denial:
 *  - `--dangerously-skip-permissions` on the agy process this hook runs under
 *    (found by walking up the process tree; Linux only). Only the flag's
 *    presence is checked; the arguments are never logged or returned.
 *  - `"toolPermission": "always-proceed"` in agy's settings.json.
 */
export function detectAgyAutoApprove(
  settingsPath = path.join(process.env.HOME || os.homedir(), ".gemini", "antigravity-cli", "settings.json"),
  startPid = process.ppid
): string | null {
  let pid = startPid;
  for (let depth = 0; depth < 8 && pid > 1; depth++) {
    let args: string[];
    let stat: string;
    try {
      args = fs.readFileSync(path.join("/proc", String(pid), "cmdline"), "utf-8").split("\0");
      stat = fs.readFileSync(path.join("/proc", String(pid), "stat"), "utf-8");
    } catch {
      break;
    }
    // Only agy's own flag counts; any other ancestor (another harness this
    // shell runs under, say) may carry a flag of the same name.
    if (/^agy(\.exe)?$/i.test(path.basename(args[0] ?? ""))) {
      if (args.includes("--dangerously-skip-permissions")) {
        return "agy was started with --dangerously-skip-permissions";
      }
      break;
    }
    pid =parseInt(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1] ?? "0", 10);
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
  autoApprove: () => string | null = detectAgyAutoApprove
): Promise<AgyPreToolUseOutput> {
  const out = await decide(rawInput, classifier);
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
      `Stop, and ask the operator to decide on this command.`,
  };
}

async function decide(rawInput: string, classifier: AutoClassifier): Promise<AgyPreToolUseOutput> {
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

  // Only run_command is intercepted by this hook; allow other tools immediately
  if (toolName !== "run_command" || !command.trim()) {
    return { decision: "allow" };
  }

  try {
    const cwd = typeof input.toolCall?.args?.Cwd === "string" && input.toolCall.args.Cwd ? input.toolCall.args.Cwd : undefined;
    const outcome = await classifier.evaluate(command, sessionId, undefined, { cwd });
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
