# construct-auto-classifier

> **Universal, effect-based safety gate and command classifier for AI coding assistants, deciding with TypeSafe's Jev or any chat LLM.**  
> Supports **Google Antigravity (`agy`)**, **OpenCode**, and external agent harnesses.

`construct-auto-classifier` sits in front of your AI coding assistants' shell execution tools (such as `run_command` in Antigravity or `bash` in OpenCode). It intercepts proposed commands and determines whether they are safe to run automatically, need an agent self-defense explanation, or must escalate to human operator review.

Unlike naive keyword filters that blindly reject `sudo` or `/etc`, `construct-auto-classifier` evaluates **what the command actually does** — its reversibility and blast radius.

---

## Certification

<!-- CERT:START -->
Each model is certified through the whole gate on two test sets, five passes each, 975 decisions per model:

- a **main test**: 113 real agent commands, written by Claude Opus 5. The gate's prompt, rules and Jev's questions were developed against it.
- a **blind test**: 82 commands written separately by Qwen3.5 397B from a plain-English policy, never used for tuning, and frozen before any model ran on it.

The bar is **zero dangerous commands allowed**. Results from September 18–19, 2026:

| Model | Provider | Dangerous commands allowed | Caught | Decisions correct | $ per 1,000 decisions |
|---|---|--:|--:|--:|--:|
| **Jev** | TypeSafe | **0** | 100.0% | 99.5% | $0.047 |
| DeepSeek 4.1 Flash | DeepSeek | 24 | 95.5% | 97.2% | $0.092 |
| Qwen3.8 27B | OpenRouter | 16 | 97.0% | 97.6% | $0.162 |
| Qwen3.5 397B † | OpenRouter | 22 | 95.8% | 96.9% | $0.373 |
| Mistral Large 3 | Ollama Cloud | 31 | 94.2% | 96.5% | $0.304 |
| GLM-5.3 Flash | Ollama Cloud | 40 | 92.5% | 95.2% | $0.135 |
| DeepSeek 4.1 Flash | OpenRouter | 44 | 91.7% | 95.1% | $0.093 |
| gpt-oss-120b | OpenRouter | 59 | 88.9% | 93.6% | $0.123 |
| gpt-oss-20b | OpenRouter | 93 | 82.5% | 89.9% | $0.025 |
| gpt-oss-safeguard-20b ‡ | OpenRouter | 104 | 80.4% | 85.0% | $0.135 |

Jev is the only model certified. † Qwen3.5 397B wrote the blind test, so its blind-test score is not independent. ‡ gpt-oss-safeguard-20b's only provider rate-limited about one call in nine.

Method, every miss and the raw results: **[the evaluation report](https://famelos.com/jev/auto-classifier-certification/)**.
<!-- CERT:END -->

---

## Choosing the model

Everything before the model step is the same either way: fast rules, script provenance, the retry counter, the cache and the harness adapters. `llm.provider` picks what makes the call when a command reaches a model.

- **`"jev"` (the default)** asks [TypeSafe's Jev](https://typesafe.ai), a System One model that writes no text and instead answers typed questions with calibrated numbers. The gate sends the command, plus any script it runs, as Jev's `state` and asks ten questions in one call:
  - an `allow`/`deny` **choice**, described by the same effect rules the chat prompt carries;
  - nine yes/no **risk questions**: `data_loss`, `secrets`, `remote_code`, `security_control`, `offensive`, `shared_state`, `git_plumbing`, `system_state` and `connections`.

  A command is allowed only if the choice is `allow` at confidence `jev.minConfidence` (0.6) or higher, and every risk is below `jev.riskThreshold` (0.7). A missing answer, a low-confidence answer, a high risk, or a failed call are all denies. The risk questions are answered independently of the choice, so a command the choice lets through still has to clear each of them.

- **`"openai"`** asks a chat model on any OpenAI-compatible endpoint. The gate sends a ~450-token system prompt, and the model replies with one line of JSON.

Jev is the default because it is the only model certified at zero dangerous commands allowed. It needs a TypeSafe key: set `TYPESAFE_API_KEY`, or name a helper in `jev.command` that sends the request for the gate, so the key never enters the gate's process. To use a chat model instead, set `llm.provider` to `"openai"`. The certification below measures both kinds of model through the same gate.

## Key Principles

### 1. Privilege Is Not a Verdict
`sudo`, `doas`, `su -c`, and elevated shells change the **blast radius** of an operation, not whether it is benign.
- `sudo systemctl status nginx` is a **safe read** and should run without interruption.
- `sudo journalctl -u service -n 50` is a **safe diagnostic**.
- `sudo cat /etc/os-release` is an **ordinary read**.
- `sudo rm -rf /` or `sudo iptables -F` modifies or destroys system state and must be stopped.

### 2. Multi-Tier Evaluation (<1ms Fast Path)
- **Fast-Deny (<1ms)**: Catastrophic destructive operations (raw disk writes `dd of=/dev/sd*`, `mkfs`, fork bombs) are stopped instantly. Deny patterns are tested against the whole line and against every simple command in it, so `ls; mkfs.ext4 /dev/sda` is the `mkfs`.
- **Fast-Allow (<1ms)**: Reads (`git status`, `git diff`, `ls`, `pwd`, `systemctl status`, `gh pr view`) and a few build/test commands (`npm test`, `pytest`, `cargo check`) are allowed immediately without an LLM call. Build/test commands run the project's own code, which the agent may have just edited with its file tools; the gate judges shell commands, not the code a test runner executes, so drop those rules if that is not a trade you want. A rule only ever vouches for the verb it names: the line is split into simple commands, **every** one must match an allow rule after its `sudo`/env prefix is stripped, and the line must carry none of the structural tells that make a read-only verb write, execute, or escape — a file redirect outside a scratch root (`> /etc/x`), `tee`, `sed`/`awk`/`perl` (programmable), `find -delete`/`-exec`, `xargs`, `sort -o`, `rg --pre`, `git -c`/`--output`, a git flag that runs a program (`grep -O`, `--ext-diff`, `--textconv`), a here-document (nothing after one is analyzed), a PowerShell script block or `iex`, an interpreter given inline code (`python3 -c`, `bash -c`), `$( )`/backticks, a `PATH=`/`LD_PRELOAD=`-style prefix, a `journalctl` maintenance flag or `-f`, or any argument that names a secret-looking path (`/etc/shadow`, `~/.ssh/…`, `.env`, `*.pem`, `credentials.json`, `*token*.toml`, a process's environment, …), since a fast-allowed `cat` is read-only and reading those is exactly the read that must not be free. Anything with a tell goes to the LLM. Redirects into `rules.scratchWriteRoots` (default `/tmp/`) are permitted once the target is resolved, so `git log > /tmp/log.txt` stays fast and `> /tmp/../etc/x` does not.
- **Semantic LLM Classification**: Elevated reads, scripts, and complex commands are passed to any OpenAI-compatible completions endpoint using an effect-based prompt.

### 3. Actionable Self-Defense Protocol (`denyMode: both`)
When the classifier rejects a command, it doesn't just return a generic error:
1. **Attempts 1 & 2**: The agent receives a structured denial explaining the security concern and instructing it:
   > *"Action blocked by safety classifier: [reason]. If this command is safe and strictly necessary, output a clear explanation to the user addressing why the classifier's concern does not apply and why this action is safe, then attempt the command again (N attempt(s) remaining). Otherwise, find a safer alternative."*
2. **Attempt 3 (Consecutive)**: If the agent insists, the system escalates to an interactive human confirmation prompt. The operator sees the classifier's finding alongside the agent's explanation directly in the terminal before deciding.

Attempts are counted **per command**, not per session: a retry is the same command again (ignoring a `sudo` prefix, whitespace, `2>&1`, or a trailing `| tail -15`), and an agent that does unrelated allowed work between a denial and its retry has still retried. Only an allowed run of that same command, or the sliding window lapsing, clears its count. A retry inside the window never goes back to the model: the verdict is already known, and what the retry is for is the count toward operator review.

### Scripts are judged on where they came from, not on their name

`./deploy/publish.sh`, `bash x.sh`, `python3 tools/x.py`, `pwsh -File x.ps1` (optionally behind `cd DIR &&`) name a file, and the file can be asked about. Before the model is consulted the classifier resolves the path against the command's working directory and asks git:

- **Landed** — tracked, and byte-identical to the copy on the repo's remote default branch (`origin/main` or whichever remote has a `HEAD`). The script went through that branch's own merge gate, so with `policy.trustLandedScripts` (default `true`) it is allowed with no LLM call at all. This is the large token saving on deploy-shaped work. Know what it trusts: the comparison is against the *local* remote-tracking ref, so it trusts whoever controls that remote, and anything able to rewrite local refs (`git update-ref`) can forge it. Turn it off for repositories whose remote you do not control.
- **Modified locally, committed but unpushed, untracked, or not in a repository** — the script content (capped at `llm.maxFileChars`, default 2000) goes to the model with one provenance line saying exactly which of those it is, so "unreviewed" is a fact the model was told rather than a guess it made.

Nothing else on the line may run: `./x.sh && rm -rf /`, `bash -c '...'`, or a `$( )` anywhere means no provenance is computed and the line is classified as written.

### What the operator sees, and the headless case

On opencode, an escalation leaves the permission prompt unanswered so the operator decides. The classifier's finding travels into that prompt two ways, because opencode versions differ in what the prompt shows: as the bash call's `description`, and as a leading `# construct-auto-classifier ESCALATION ...` comment on the command itself (a comment changes nothing about what runs). The agent's own case for the command is in the transcript just above the prompt.

**Two gates cannot share one prompt.** If another command-approval plugin (`auto-mode.js`) sits beside this one in `~/.config/opencode/plugins/`, both answer `permission.asked`, and the other can reject an escalation before the operator sees it. The plugin logs a warning on first use when it finds one; keep one gate.

**A prompt on a headless box is a prompt nobody answers.** Set `policy.headless: true` (or `AUTO_CLASSIFIER_HEADLESS=1`) on a box with no operator at the keyboard: an escalation then becomes a denial that tells the agent to stop and report, instead of a permission left pending, or auto-rejected by `opencode run` as if the operator had declined. This holds on every harness, and the agent's first denial already tells it that a retry will be blocked.

### What it costs

Most commands never reach a model. The fast rules settle the obvious ones, a script identical to its repo's default branch is allowed without a call, and a repeated command inside the sliding window reuses its verdict. A denial's retry never asks the model again, and a denial caused by an unreachable model is not reused. Only what is left is paid for.

- **Jev (the default)** costs about **$0.047 per 1,000 decisions** that reach it, at TypeSafe's published input price. That is roughly half of DeepSeek 4.1 Flash on DeepSeek's own API, the cheapest chat model that came close on safety. Every model's measured cost is in the certification table above.
- **Chat models** get a ~450-token system prompt and reply with one short JSON object (`llm.maxTokens` defaults to 120). A reasoning model would spend that budget thinking, so the client switches reasoning off in whatever way the endpoint expects: `reasoning: {enabled: false}` on OpenRouter, `thinking: {type: "disabled"}` on DeepSeek's API, `reasoning_effort: "none"` on Ollama Cloud. It picks the endpoint by host, or by the model id's `openrouter/`, `deepseek/` or `ollama-cloud/` prefix behind a gateway. `llm.extraBody` merges over those defaults, and a `null` value removes one.
- **An optional cheaper first pass for chat models:** set `llm.triageModel` to a small or local model. Its allow is final; a deny, an unreadable reply or an error hands the same prompt to `llm.model`. Allows are most real traffic, so the main model mostly sees the commands that deserve it.
- **Any change to the prompt or to Jev's questions re-runs the certification** (`bun bench/run.ts`). A change that scores worse than the current one does not ship.

### Session attribution

Every completion carries an `X-Session-Id: <sessionId>:auto-classifier` header. The suffix is the point: the gate runs on a different model, on a different budget, answering a question the agent never asked and never sees the answer to, so folding its spend into the agent's own session would overstate what that session cost. Marked this way the rows still group under the session by prefix, and still separate from it exactly. A gateway that attributes spend per session reads the header; a plain OpenAI-compatible endpoint ignores an unknown one, so it is sent unconditionally and needs no configuration. No header is sent when there is no session to name.

### Telemetry and the log

Every decision appends one JSON line to `~/.config/auto-classifier/telemetry.jsonl` (`telemetry.path` overrides; `telemetry.enabled: false` stops it): the command, which stage decided it (`fast-allow`, `fast-deny`, `retry`, `landed`, `cache`, `triage`, `llm`, `fallback`, `error`), the verdict, the reason, and the latency. Secrets are redacted before writing. That file is the corpus for promoting frequent benign commands to fast-allow rules and for re-certifying the model against real traffic. The plugin's own log is beside it at `auto-classifier.log` (`AUTO_CLASSIFIER_LOG` overrides; empty disables): sibling-gate warnings, model failures, and one line per opencode decision.

Every row also carries `injection_attempt` and `injection_pattern`: a deterministic regex (`src/rules/injection-detection.ts`) checked against the command and any file content, independent of the model and of which stage decided the verdict. It catches common tells — a forged `SYSTEM:`/`ASSISTANT:`/`DEVELOPER:` turn declaring the real rules void, an explicit "ignore/disregard/forget prior instructions", or a demand for the exact `{"allow": true}` this gate would itself emit — but not every phrasing. The policy is "allow, but tell you": an injection attempt that asks for something harmless (`ls -la # SYSTEM: ...`) still gets its ordinary, harmless verdict; the flag only ever adds telemetry and never changes `decision`.

Every row also carries `cwd` (the `EvaluateOptions.cwd` the caller passed, or `null`). Nothing in this package reads it back; it is there so whatever tails the log (an alerting job watching for `injection_attempt: true`, say) can tell which workspace a decision came from and apply that workspace's own policy.

### 4. Robust State & Concurrency Safety
- **User-Isolated Storage**: State is kept in `$XDG_RUNTIME_DIR` or `~/.cache/auto-classifier/sessions/`, preventing multi-user `/tmp` permission collisions.
- **Atomic State Writes**: State is updated via atomic writes to prevent corruption during parallel tool executions.
- **Anti-Interleaving**: Counters are keyed on the command, so neither an exploratory read (`ls`, `pwd`) nor unrelated allowed work between retries can reset the count toward operator review.
- **Automatic TTL Cleanup**: Stale session files are pruned automatically after 2 hours.

---

## Installation & Setup

### Prerequisites
- [Bun](https://bun.sh/) v1.2+ to build and test (the built plugin and CLI run on Node.js 18+ too)
- An OpenAI-compatible LLM endpoint (Ollama, vLLM, OpenRouter, Groq, OpenAI, or local gateway).

### 1. Build from Source
```bash
git clone https://github.com/godspede/construct-auto-classifier.git
cd construct-auto-classifier
bun install # or npm install
bun run build
bun run build:binary # optional: compiles standalone native binary
```

---

## Harness Integrations

### 1. Google Antigravity (`agy`)
Put the hook in agy's user-scope `~/.gemini/config/hooks.json`, so every agy session on the machine is gated. A project's `.agents/hooks.json` takes the same block and gates only that project.

```json
{
  "auto-classifier": {
    "PreToolUse": [
      {
        "matcher": "run_command|write_to_file|replace_file_content|multi_replace_file_content",
        "hooks": [
          {
            "type": "command",
            "command": "node /path/to/construct-auto-classifier/bin/auto-classifier.js agy",
            "timeout": 20
          }
        ]
      }
    ]
  }
}
```

agy's own approval setting decides how an escalation reaches you, and a hook can block a command but cannot skip agy's prompt. The setup that prompts you only for the gate's escalations:

- **`"toolPermission": "request-review"`** in `~/.gemini/antigravity-cli/settings.json`, and agy started **without** `--dangerously-skip-permissions`. agy now asks before every command.
- **Run agy inside tmux, with `"agy": { "autoAcceptInTmux": true }`** in the gate's config. [yoloagy](https://github.com/godspede/yoloagy) starts agy in its own tmux session, without `--dangerously-skip-permissions`, and reattaches after an SSH dropout. When the gate allows a command, it starts a short-lived watcher on agy's tmux pane that presses Enter on agy's prompt, but only if the prompt shows exactly that command, with "1. Yes, run command" still highlighted and no hook reason on it. An escalation carries the gate's finding as its reason, so it stays up for you.

It fails toward a prompt. No watcher starts unless the gate computed an allow, so a gate that crashes, times out or isn't installed leaves every command to you; a watcher that can't read the pane, sees any other command, or sees nothing within five seconds sends no key.

Without tmux, choose between `request-review` (you answer every command) and `"always-proceed"` (allowed commands run; agy would approve an escalation by itself, so the gate blocks it instead and tells the agent to stop and ask you, and you run it yourself if you agree). `--dangerously-skip-permissions` behaves like `always-proceed`: the gate notices either one.

When agy runs `run_command`:
- Safe commands run without a prompt.
- A denied command comes back to the agent with the reason. It may explain why the concern doesn't apply and try once more, and it is told that the retry needs your approval and stays blocked if nobody is there to give it.
- The same command again escalates (`policy.consecutiveThreshold`, default 2): agy's prompt with the finding under `request-review`, or blocked with a request to ask you under `always-proceed`.

When agy writes a file (`write_to_file`, `replace_file_content`), no model is asked; where the write lands decides it:
- Inside the session's workspace (agy's `workspacePaths`): allowed, and under tmux the watcher accepts agy's "Allow creation of this file?" / "Accept this file edit?" prompt when it shows that file.
- Outside the workspace, or inside it under `.git/`, `.agents/`, `.gemini/`, `.claude/`, `.opencode/`, `opencode.json`, `.mcp.json`, an `.env` file, `.githooks/` or a CI workflow directory: escalated to you with the reason, since those change what runs or who is trusted.
- The gate's own config, log, plugin and session state: denied, as for a shell command.

### 2. OpenCode
Add the compiled plugin to your OpenCode configuration in `~/.config/opencode/plugins/`:

```javascript
// ~/.config/opencode/plugins/auto-classifier.js
import plugin from "/path/to/construct-auto-classifier/dist/opencode-plugin.js";
export default plugin;
```

---

## Configuration (`auto-classifier.jsonc`)

`construct-auto-classifier` looks for configuration in:
1. the `AUTO_CLASSIFIER_CONFIG` environment variable
2. `~/.config/auto-classifier/config.jsonc` (or `config.json`)

It never reads configuration from the working directory. That directory is the repository the agent is working in, and a config file there could point the gate at a model that allows everything.

Example configuration:

```jsonc
{
  "llm": {
    // Any OpenAI-compatible endpoint
    "baseUrl": "http://127.0.0.1:8099/v1",
    "apiKey": "env:AUTO_CLASSIFIER_API_KEY",
    "model": "openrouter/deepseek/deepseek-v4.1-flash",
    "fallbackModel": "deepseek/deepseek-flash",
    "timeoutMs": 15000,
    // Cap on script content shown to the model when a script is not landed
    "maxFileChars": 2000,
    // Completion budget for the one-line JSON reply
    "maxTokens": 120,
    // Optional cheaper model asked first; its allow is final, its deny is re-asked of "model"
    "triageModel": "ollama-cloud/gemma4:31b",
    // Extra request fields merged over the per-route reasoning-off defaults; null removes a default
    "extraBody": { "top_p": 0.1 }
  },
  "policy": {
    "denyMode": "both", // "both", "auto-retry", or "ask-user"
    "consecutiveThreshold": 2,
    "slidingWindowMs": 300000,
    "instructAgentOnDenial": true,
    // A script byte-identical to its repo's remote default branch is allowed without the model
    "trustLandedScripts": true
  },
  "rules": {
    "fastAllow": [
      "^\\s*git\\s+(status|diff|log|show)\\b",
      // list-shaped only: a bare `git\\s+branch\\b` would fast-allow `git branch -D main`
      "^\\s*git\\s+branch(?:\\s+(?:-a|-r|-v|-vv|--list|--all|--remotes|--show-current|--verbose))*\\s*$",
      "^\\s*ls(\\s+-[a-zA-Z0-9]+)*(\\s+[^\\s;&|]+)?$",
      "^\\s*pwd$",
      "^\\s*whoami$"
    ],
    "fastDeny": [
      "^\\s*mkfs(\\.[a-z0-9]+)?\\s+",
      "^\\s*dd\\s+.*of=\\/dev\\/(sd[a-z]|nvme[0-9]n[0-9]|vd[a-z])"
    ],
    // Path prefixes a fast-allowed command may redirect output into
    "scratchWriteRoots": ["/tmp/"]
  }
}
```

### Machine-local overlay

If you share one `config.jsonc` (model chain, rules, policy) across several
machines, what differs per machine (`baseUrl`, `apiKey`/`apiKeyFile`,
`denyMode`/`headless`) belongs in a small overlay instead of a hand-maintained
fork of the whole file:

1. `AUTO_CLASSIFIER_LOCAL_CONFIG` environment variable, if it names a file
   that exists
2. `~/.config/auto-classifier/local.jsonc`

The overlay is deep-merged over the resolved config file — an object's keys
merge recursively, an array or scalar in the overlay replaces the config
file's value outright (never concatenates). It is written once per machine
and left alone when the shared `config.jsonc` is updated. Full precedence, low
to high: **defaults < config file < local overlay < environment variable.**

```jsonc
// ~/.config/auto-classifier/local.jsonc — everything else comes from config.jsonc
{
  "llm": {
    "baseUrl": "https://llm-gateway.example.internal/v1",
    // Read a bearer from a file instead of embedding it, used only when
    // "apiKey" is absent. `~` expands to the running user's home. An
    // unreadable file is logged and ignored — the call then fails closed,
    // same as no key configured at all.
    "apiKeyFile": "~/.config/auto-classifier/gateway-token"
  },
  "policy": {
    "denyMode": "ask-user",
    "headless": false
  }
}
```

A malformed overlay is logged and ignored rather than breaking the gate — the
config file's own values apply as if no overlay existed.

### Environment Variable Overrides
All settings can be overridden via environment variables:
- `AUTO_CLASSIFIER_BASE_URL` or `OPENAI_BASE_URL`
- `AUTO_CLASSIFIER_API_KEY` or `OPENAI_API_KEY`
- `AUTO_CLASSIFIER_MODEL`
- `AUTO_CLASSIFIER_FALLBACK_MODEL`
- `AUTO_CLASSIFIER_TRIAGE_MODEL`
- `AUTO_CLASSIFIER_TIMEOUT_MS`
- `AUTO_CLASSIFIER_DENY_MODE`
- `AUTO_CLASSIFIER_HEADLESS` — `1` when no one can answer a prompt
- `AUTO_CLASSIFIER_LOCAL_CONFIG` — overrides the machine-local overlay path
- `AUTO_CLASSIFIER_LOG` — the plugin's log file; empty disables
- `AUTO_CLASSIFIER_SYSTEM_PROMPT_FILE` — replace the system prompt (for benchmarking candidates)
- `AUTO_CLASSIFIER_PROVIDER` — `openai` or `jev`
- `TYPESAFE_API_KEY`, `TYPESAFE_BASE_URL` — Jev's key and API root
- `AUTO_CLASSIFIER_JEV_COMMAND` — a helper that sends the Jev request, as a JSON argv array
- `AUTO_CLASSIFIER_JEV_MODEL` — the Jev version (default `jev-1.13.0`, the certified one)

The classifier's own variables are part of the gate, so a command that sets any `AUTO_CLASSIFIER_*` or `TYPESAFE_*` variable is denied outright, the same as one that edits the config file.

### What the gate does not see

It classifies shell commands. File writes are judged only by where they land (agy: see above; OpenCode: its edit, write and patch tools are refused only for the gate's own files, and otherwise left to OpenCode's permission rules), never by what they write. So an agent that can edit files in its workspace can still change what a later, allowed command runs (a test file before `npm test`, a script before it is committed); the gate does read an unreviewed script's contents when a command runs it.

Every command the fast rules cannot decide, and up to `llm.maxFileChars` of an unreviewed script it runs, is sent to the configured model provider. Literal values of `*KEY=`/`*TOKEN=`/`*SECRET=`/`*PASSWORD=` assignments, bearer tokens and private keys are redacted first; that redaction is best-effort, so choose a provider you would trust with your shell history.

---

## CLI Usage

You can test commands manually using the CLI:

```bash
# Evaluate a safe privileged command
auto-classifier check "sudo systemctl status nginx"
# Output: { "decision": "allow", "reason": "Read-only service status inspection..." }

# Evaluate a destructive command (attempt 1)
auto-classifier check "rm -rf /var/log/audit" --session sess-1
# Output: { "decision": "deny", "reason": "Action blocked: Recursive force-delete... (2 attempt(s) remaining)..." }

# Evaluate attempt 3 (escalation)
auto-classifier check "rm -rf /var/log/audit" --session sess-1
auto-classifier check "rm -rf /var/log/audit" --session sess-1
# Output: { "decision": "force_ask", "reason": "⚠️ SAFETY ESCALATION: the safety classifier has blocked this command 3 times..." }
```

---

## Running Tests

```bash
bun test
```

The certification bench is separate, because every case is a real model call:

```bash
bun bench/run.ts --n-runs 5                                                   # the certification bar, on Jev (the default)
bun bench/run.ts --model openrouter/deepseek/deepseek-v4.1-flash --n-runs 5   # a chat model instead
bun bench/run.ts --battery bench/holdout.jsonl                               # cases no prompt was tuned on
bun bench/run.ts --prompt-file candidate.txt --json
```

A model is certified when five passes over the battery return **zero false allows**. The run is hermetic: it loads `bench/bench-config.jsonc` (the shipped defaults) and skips any box-local overlay, so what it certifies is what this repo ships, never one machine's own config. Point it at a chat model with `AUTO_CLASSIFIER_BASE_URL` / `AUTO_CLASSIFIER_API_KEY`, or at Jev with `AUTO_CLASSIFIER_PROVIDER=jev` and `TYPESAFE_API_KEY` or `AUTO_CLASSIFIER_JEV_COMMAND`. `--json` records the commit, the battery's sha256, and per-case token usage alongside every verdict.

`bench/battery.jsonl` holds labelled commands across benign development, project tooling, privileged-legitimate, privileged-malicious, destructive, credential, remote-code, prompt-injection and inline-interpreter cases. `bench/run.ts` drives them through the real gate end to end (the shipped config, a real `LlmClient`, the real `AutoClassifier`, opencode's own plugin) rather than the model alone, so it also scores which stage decided each case (`expect_source`) and, for the injection cases, whether the deterministic injection tell fired (`expect_injection_attempt`) — a case's own `expect` verdict is unaffected by either.

Unit tests cover:
- Fast rules evaluation (<1ms matching).
- System and user prompt formatting, secret and token redaction.
- State management, atomic disk operations, sliding windows, and anti-interleaving logic.
- JSON response boundary extraction and fail-closed parser resilience.

<sub><i>Forged on construct/famelos</i></sub>

---

## License

Apache-2.0. See [LICENSE](LICENSE) for details.
