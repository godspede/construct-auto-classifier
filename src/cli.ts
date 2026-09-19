import { runAgyHook } from "./adapters/agy.js";
import { runAcceptWatcher } from "./adapters/agy-accept.js";
import { AutoClassifier } from "./index.js";
import { loadConfig } from "./config.js";
import { VERSION } from "./version.js";

async function main() {
  const args = process.argv.slice(2);
  const command = args[0] || "agy";

  if (command === "agy") {
    // Run Antigravity PreToolUse hook
    await runAgyHook();
    return;
  }

  if (command === "agy-accept" && args[1]) {
    // The watcher the agy hook starts for an allowed command (agy-accept.ts).
    await runAcceptWatcher(args[1]);
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
    const outcome = await classifier.evaluate(cmdToCheck, sessionId);
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
    console.log(`
construct-auto-classifier (v${VERSION})
Effect-based safety gate for AI coding agents' shell commands.

Usage:
  auto-classifier agy                       Run Antigravity PreToolUse hook (reads stdin)
  auto-classifier check "<cmd>"             Test a command against the classifier
  auto-classifier check "<cmd>" --session X Evaluate within a specific session
  auto-classifier config                    Print resolved configuration
  auto-classifier version                   Print the version
  auto-classifier help                      Show this help message

Environment Variables:
  AUTO_CLASSIFIER_CONFIG      Path to the config file (default ~/.config/auto-classifier/config.jsonc)
  AUTO_CLASSIFIER_BASE_URL    OpenAI-compatible completions URL (or OPENAI_BASE_URL; default OpenRouter)
  AUTO_CLASSIFIER_API_KEY     API Key (or OPENAI_API_KEY)
  AUTO_CLASSIFIER_MODEL       Model name (default deepseek/deepseek-v4.1-flash)
  AUTO_CLASSIFIER_FALLBACK_MODEL  Model tried when the primary fails (default none)
  AUTO_CLASSIFIER_TIMEOUT_MS  Per-request timeout (default 15000)
  AUTO_CLASSIFIER_TRIAGE_MODEL    Optional cheaper model asked first; its allow is final
  AUTO_CLASSIFIER_DENY_MODE   "both" | "auto-retry" | "ask-user"
  AUTO_CLASSIFIER_HEADLESS    1 = no one can answer a prompt here; escalations deny and say so
  AUTO_CLASSIFIER_LOG         Log file path (default ~/.config/auto-classifier/auto-classifier.log; empty disables)
  AUTO_CLASSIFIER_SYSTEM_PROMPT_FILE  Replace the built-in system prompt (bench use)
  AUTO_CLASSIFIER_PROVIDER    "jev" (TypeSafe's Jev, the default) | "openai" (a chat model)
  TYPESAFE_API_KEY            Jev API key
  TYPESAFE_BASE_URL           Jev API root (default https://api.typesafe.ai)
  AUTO_CLASSIFIER_JEV_COMMAND Helper that sends the Jev request for this process, as a JSON argv array
  AUTO_CLASSIFIER_JEV_MODEL   Jev model (default jev-1.13.0, the certified version)
`);
    return;
  }

  console.error(`Unknown subcommand: ${command}. Run 'auto-classifier help' for usage.`);
  process.exit(1);
}

main().catch((err) => {
  console.error("[auto-classifier] Fatal error:", err);
  process.exit(1);
});
