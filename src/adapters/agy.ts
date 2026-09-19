import { AutoClassifier } from "../index.js";
import { log } from "../log.js";
import type { AgyPreToolUseInput, AgyPreToolUseOutput } from "../types.js";

/**
 * The Antigravity PreToolUse hook, as a pure function: raw stdin text in, the
 * JSON object to print on stdout out. `runAgyHook` is the thin process wrapper.
 */
export async function handleAgyInput(rawInput: string, classifier: AutoClassifier): Promise<AgyPreToolUseOutput> {
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
