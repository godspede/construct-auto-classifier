import { runAgyHook, handleAgyPreInvocation } from "./adapters/agy.js";
import { runAcceptWatcher, runEscalationWatcher } from "./adapters/agy-accept.js";
import { AutoClassifier } from "./index.js";
import { loadConfig } from "./config.js";
import { VERSION } from "./version.js";

const HELP = `
construct-auto-classifier (v${VERSION})
Effect-based safety gate for AI coding agents' shell commands and file tools.

Usage:
  auto-classifier agy                       Antigravity hook, reading agy's event on stdin: wire it as both
                                            PreToolUse (gates each tool call) and PreInvocation (tells the
                                            agent an escalation was declined because nobody answered)
  auto-classifier check "<cmd>"             Test a command against the classifier
  auto-classifier check "<cmd>" --session X Evaluate within a specific session
  auto-classifier config                    Print resolved configuration
  auto-classifier version                   Print the version
  auto-classifier help                      Show this help message

Environment Variables (each overrides the config field named; see the README):
  AUTO_CLASSIFIER_CONFIG              Config file path (default ~/.config/auto-classifier/config.jsonc)
  AUTO_CLASSIFIER_LOCAL_CONFIG        Machine-local overlay path (default ~/.config/auto-classifier/local.jsonc)
  AUTO_CLASSIFIER_PROVIDER            llm.provider: "jev" (TypeSafe's Jev, the default) | "openai" (a chat model)
  AUTO_CLASSIFIER_BASE_URL            llm.baseUrl, an OpenAI-compatible API root (or OPENAI_BASE_URL; default OpenRouter)
  AUTO_CLASSIFIER_API_KEY             llm.apiKey (or OPENAI_API_KEY)
  AUTO_CLASSIFIER_MODEL               llm.model (default deepseek/deepseek-v4.1-flash)
  AUTO_CLASSIFIER_FALLBACK_MODEL      llm.fallbackModel, tried when the primary fails (default none)
  AUTO_CLASSIFIER_FALLBACK_MODELS     llm.fallbackModels, comma-separated, tried after it
  AUTO_CLASSIFIER_TRIAGE_MODEL        llm.triageModel, a cheaper model asked first; its allow is final
  AUTO_CLASSIFIER_TIMEOUT_MS          llm.timeoutMs, one request's timeout (default 15000)
  AUTO_CLASSIFIER_TOTAL_TIMEOUT_MS    llm.totalTimeoutMs, the whole model chain's deadline (default 18000)
  AUTO_CLASSIFIER_DENY_MODE           policy.denyMode: "both" | "auto-retry" | "ask-user"
  AUTO_CLASSIFIER_HEADLESS            policy.headless: 1 = nobody can answer a prompt here; escalations deny and say so
  AUTO_CLASSIFIER_TIMEOUT_MINUTES     policy.escalationTimeoutMinutes (default 5)
  AUTO_CLASSIFIER_PROTECTED_BRANCHES  policy.protectedBranches, comma-separated (default main,master)
  AUTO_CLASSIFIER_INSTRUCTIONS_APPEND policy.instructionsAppend, used only when no config file sets it
  AUTO_CLASSIFIER_LOG                 Log file path (default ~/.config/auto-classifier/auto-classifier.log; empty disables)
  AUTO_CLASSIFIER_STATE_DIR           Where agy's escalation-timeout records go (<dir>/timeouts/; default ~/.config/auto-classifier)
  AUTO_CLASSIFIER_SYSTEM_PROMPT_FILE  Replace the built-in chat system prompt (bench use)
  TYPESAFE_API_KEY                    Jev API key
  TYPESAFE_BASE_URL                   Jev API root (default https://api.typesafe.ai)
  AUTO_CLASSIFIER_JEV_COMMAND         jev.command: a helper that sends the Jev request, as a JSON argv array
  AUTO_CLASSIFIER_JEV_MODEL           jev.model (default jev-1.13.0, the certified version)
`;

async function main() {
  const args = process.argv.slice(2);
  // With no arguments the hook reads agy's event on stdin. A person typing the
  // bare command at a terminal gets the help instead of a silent wait.
  if (!args[0] && process.stdin.isTTY) {
    console.log(HELP);
    return;
  }
  const command = args[0] || "agy";

  if (command === "agy") {
    // Run Antigravity PreToolUse / PreInvocation hook
    await runAgyHook();
    return;
  }

  if (command === "agy-accept" && args[1]) {
    // The watcher the agy hook starts for an allowed command (agy-accept.ts).
    await runAcceptWatcher(args[1]);
    return;
  }

  if (command === "agy-timeout" && args[1]) {
    // The watcher that auto-denies agy's prompt after the escalation timeout.
    await runEscalationWatcher(args[1]);
    return;
  }

  if (command === "agy-pre-invocation") {
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
    const rawInput = Buffer.concat(chunks).toString("utf-8");
    try {
      const parsed = JSON.parse(rawInput.trim());
      const output = handleAgyPreInvocation(parsed);
      process.stdout.write(JSON.stringify(output) + "\n");
    } catch {
      process.stdout.write(JSON.stringify({ injectSteps: [] }) + "\n");
    }
    return;
  }

  if (command === "check") {
    const cmdToCheck = args[1];
    if (!cmdToCheck) {
      console.error("Usage: auto-classifier check \"<command>\" [--session <id>]");
      process.exit(1);
    }
    const sessionIdx = args.indexOf("--session");
    const sessionId = sessionIdx !== -1 && args[sessionIdx + 1] ? args[sessionIdx + 1] : "cli-check-session";

    const classifier = new AutoClassifier();
    const outcome = await classifier.evaluate(cmdToCheck, sessionId, undefined, { cwd: process.cwd() });
    console.log(JSON.stringify(outcome, null, 2));
    process.exit(outcome.decision === "allow" ? 0 : 2);
  }

  if (command === "config") {
    const config = loadConfig();
    const masked = {
      ...config,
      llm: { ...config.llm, apiKey: config.llm.apiKey ? "[set]" : "" },
      jev: { ...config.jev, apiKey: config.jev.apiKey ? "[set]" : "" },
    };
    console.log(JSON.stringify(masked, null, 2));
    return;
  }

  if (command === "version" || command === "--version" || command === "-v") {
    console.log(VERSION);
    return;
  }

  if (command === "help" || command === "--help" || command === "-h") {
    console.log(HELP);
    return;
  }

  console.error(`Unknown subcommand: ${command}. Run 'auto-classifier help' for usage.`);
  process.exit(1);
}

main().catch((err) => {
  console.error("[auto-classifier] Fatal error:", err);
  process.exit(1);
});
