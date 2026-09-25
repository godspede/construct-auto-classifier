import fs from "node:fs";
import path from "node:path";
import type { AppConfig, JevConfig } from "./types.js";
import { parseSanctionedEntry } from "./rules/uploads.js";
import { log } from "./log.js";
import { DEFAULT_TELEMETRY_MAX_BYTES } from "./telemetry.js";
import { DEFAULT_PROTECTED_BRANCHES, isBranchName, pushFastAllowRule } from "./protected-branches.js";
import { gateConfigDir, homeDir } from "./paths.js";
import { protectGateFile } from "./rules/self-protection.js";

function stripJsonComments(jsonc: string): string {
  let insideString = false;
  let quoteChar = "";
  let isEscaped = false;
  let out = "";
  let i = 0;

  while (i < jsonc.length) {
    const ch = jsonc[i];
    const next = jsonc[i + 1];

    if (insideString) {
      out += ch;
      if (isEscaped) {
        isEscaped = false;
      } else if (ch === "\\") {
        isEscaped = true;
      } else if (ch === quoteChar) {
        insideString = false;
      }
      i++;
      continue;
    }

    if (ch === '"' || ch === "'") {
      insideString = true;
      quoteChar = ch;
      out += ch;
      i++;
      continue;
    }

    // Check for single-line comment //
    if (ch === "/" && next === "/") {
      while (i < jsonc.length && jsonc[i] !== "\n" && jsonc[i] !== "\r") {
        i++;
      }
      continue;
    }

    // Check for multi-line comment /* ... */
    if (ch === "/" && next === "*") {
      i += 2;
      while (i < jsonc.length && !(jsonc[i] === "*" && jsonc[i + 1] === "/")) {
        i++;
      }
      i += 2;
      continue;
    }

    out += ch;
    i++;
  }

  // Strip trailing commas before } or ]
  return out.replace(/,(\s*[}\]])/g, "$1");
}

export function parseJsonc<T>(content: string): T {
  const stripped = stripJsonComments(content);
  return JSON.parse(stripped) as T;
}

export function resolveApiKey(apiKey?: string): string {
  if (!apiKey) return "";
  if (apiKey.startsWith("env:")) {
    const varName = apiKey.slice(4).trim();
    return process.env[varName] || "";
  }
  return apiKey;
}

function expandHome(p: string): string {
  return p.replace(/^~(?=[\/\\]|$)/, homeDir());
}

/**
 * `apiKeyFile` and `AUTO_CLASSIFIER_LOCAL_CONFIG` both name a path from an
 * untrusted source (a config file value, an env var) and are read back by
 * the gate itself — an unchecked read is an arbitrary-file-read primitive
 * for whatever process can influence either. Every legitimate use (the
 * README's own example, the default overlay path) resolves under the
 * running user's home, so anything else is refused. The working directory is
 * deliberately not a root: it is the repository the agent is working in, and
 * its contents are exactly what the gate must not trust.
 */
function isWithinAllowedRoots(resolved: string): boolean {
  const roots = [homeDir()];
  return roots.some((root) => {
    const rel = path.relative(path.resolve(root), resolved);
    return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
  });
}

/** Trimmed contents of `llm.apiKeyFile`, or "" — logged and never thrown. */
export function readApiKeyFile(filePath?: string): string {
  if (!filePath) return "";
  const resolved = path.resolve(expandHome(filePath));
  if (!isWithinAllowedRoots(resolved)) {
    console.error(
      `[auto-classifier] Warning: refusing to read llm.apiKeyFile outside your home directory: ${resolved}`
    );
    return "";
  }
  try {
    return fs.readFileSync(resolved, "utf-8").trim();
  } catch (err) {
    console.error(`[auto-classifier] Warning: failed to read llm.apiKeyFile at ${resolved}:`, err);
    return "";
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * agy.alwaysProceedEscalations: missing means "run"; a value that is neither
 * "run" nor "stop" (a typo of "stop", say) fails closed to "stop", and says so.
 */
function readAlwaysProceedEscalations(value: unknown): "run" | "stop" {
  if (value === undefined || value === "run") return "run";
  if (value !== "stop") {
    log(`config: agy.alwaysProceedEscalations ${JSON.stringify(value)} is not "run" or "stop" -- treating it as "stop"`);
  }
  return "stop";
}

/**
 * Merge `overlay` over `base`: plain objects merge key by key, recursively;
 * an array or scalar in `overlay` replaces `base`'s value outright rather
 * than concatenating or splicing. Used to fold the machine-local overlay over
 * the shared config file — the shared model chain and rules survive
 * untouched while an overlay-named `baseUrl`/`apiKey`/`denyMode` wins.
 */
export function deepMerge<T>(base: T, overlay: Partial<T>): T {
  if (!isPlainObject(base) || !isPlainObject(overlay)) {
    return (overlay as T) ?? base;
  }
  const out: Record<string, unknown> = { ...(base as Record<string, unknown>) };
  for (const [key, value] of Object.entries(overlay)) {
    const baseValue = (base as Record<string, unknown>)[key];
    out[key] = isPlainObject(baseValue) && isPlainObject(value) ? deepMerge(baseValue, value) : value;
  }
  return out as T;
}

/**
 * The machine-local overlay: `AUTO_CLASSIFIER_LOCAL_CONFIG` if it names a file
 * that exists, else `~/.config/auto-classifier/local.jsonc`. Never the same
 * file as the shared config — it holds only what differs per machine (baseUrl,
 * apiKey/apiKeyFile, denyMode/headless) and is written once, and left alone
 * when a shared `config.jsonc` is updated.
 */
export function findLocalOverlayFile(): string | null {
  const override = process.env.AUTO_CLASSIFIER_LOCAL_CONFIG;
  if (override) {
    const resolved = path.resolve(expandHome(override));
    protectGateFile(resolved);
    if (!isWithinAllowedRoots(resolved)) {
      console.error(
        `[auto-classifier] Warning: refusing AUTO_CLASSIFIER_LOCAL_CONFIG outside your home directory: ${resolved}`
      );
    } else if (fs.existsSync(resolved)) {
      return resolved;
    }
  }
  const defaultPath = path.join(gateConfigDir(), "local.jsonc");
  if (fs.existsSync(defaultPath)) {
    return defaultPath;
  }
  return null;
}

export function findConfigFile(explicitPath?: string): string | null {
  if (explicitPath && fs.existsSync(explicitPath)) {
    return explicitPath;
  }
  const fromEnv = process.env.AUTO_CLASSIFIER_CONFIG;
  if (fromEnv) {
    if (fs.existsSync(fromEnv)) return fromEnv;
    // Said loudly: the gate is about to run on a config nobody chose for it.
    const msg = `AUTO_CLASSIFIER_CONFIG names ${path.resolve(fromEnv)}, which does not exist; falling back to ${path.join(gateConfigDir(), "config.jsonc")} or the built-in defaults`;
    console.error(`[auto-classifier] Warning: ${msg}`);
    log(msg);
  }

  // Never the working directory: a cloned repository, or the agent itself with
  // its file tools, could otherwise ship a config that points the gate at a
  // model that allows everything.
  const candidates = [
    path.join(gateConfigDir(), "config.jsonc"),
    path.join(gateConfigDir(), "config.json"),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  return null;
}

/**
 * `sanctionedRemotes` (inline) plus the entries of the JSON file
 * `sanctionedRemotesFile` names: an array of patterns, or an object whose
 * `sanctionedRemotes`, `remotes` or `entries` array holds them (strings, or
 * objects with a `pattern`). Unparseable patterns are dropped with a warning.
 * A file that cannot be read contributes nothing and says so: with no entries
 * at all only loopback is sanctioned, which is the safe failure.
 */
export function loadSanctionedRemotes(fileConfig: Record<string, any>): string[] {
  const out: string[] = [];
  const take = (list: unknown, from: string) => {
    if (!Array.isArray(list)) {
      if (list !== undefined) console.error(`[auto-classifier] Warning: ${from} is not an array; ignoring it`);
      return;
    }
    for (const item of list) {
      const pattern = typeof item === "string" ? item : isPlainObject(item) && typeof item.pattern === "string" ? item.pattern : undefined;
      if (pattern !== undefined && parseSanctionedEntry(pattern)) out.push(pattern.trim().toLowerCase());
      else console.error(`[auto-classifier] Warning: ${from} has an entry that is not a host pattern; ignoring it`);
    }
  };
  take(fileConfig.sanctionedRemotes, "sanctionedRemotes");
  const file = fileConfig.sanctionedRemotesFile;
  if (typeof file === "string" && file) {
    const resolved = path.resolve(expandHome(file));
    // It decides where uploads may go: a gate file, whether or not it exists yet.
    protectGateFile(resolved);
    try {
      const parsed = JSON.parse(fs.readFileSync(resolved, "utf-8"));
      const list = Array.isArray(parsed)
        ? parsed
        : isPlainObject(parsed)
          ? (parsed.sanctionedRemotes ?? parsed.remotes ?? parsed.entries)
          : undefined;
      take(list ?? [], `sanctionedRemotesFile ${resolved}`);
    } catch (err) {
      const msg = `sanctionedRemotesFile ${resolved} is unreadable (${(err as Error).message}); it sanctions nothing`;
      console.error(`[auto-classifier] Warning: ${msg}`);
      log(msg);
    }
  }
  return [...new Set(out)];
}

/**
 * `policy.protectedBranches`, or `AUTO_CLASSIFIER_PROTECTED_BRANCHES`
 * (comma-separated) over it. A value that is not a list falls back to the
 * default rather than to no protection at all; an entry that is not a branch
 * name is dropped, and each says so. An explicitly empty list protects
 * nothing, which is the config's own choice.
 */
function readProtectedBranches(fromFile: unknown): string[] {
  const env = process.env.AUTO_CLASSIFIER_PROTECTED_BRANCHES;
  const raw: unknown = env !== undefined && env.trim() !== "" ? env.split(",") : fromFile;
  if (raw === undefined) return [...DEFAULT_PROTECTED_BRANCHES];
  if (!Array.isArray(raw)) {
    console.error(`[auto-classifier] Warning: policy.protectedBranches is not an array; using ${DEFAULT_PROTECTED_BRANCHES.join(", ")}`);
    return [...DEFAULT_PROTECTED_BRANCHES];
  }
  const out: string[] = [];
  for (const item of raw) {
    const name = typeof item === "string" ? item.trim() : "";
    if (name && isBranchName(name)) out.push(name);
    else if (!(typeof item === "string" && name === "")) {
      console.error(`[auto-classifier] Warning: policy.protectedBranches entry ${JSON.stringify(item)} is not a branch name; ignoring it`);
    }
  }
  if (out.length === 0 && raw.length > 0) {
    console.error(`[auto-classifier] Warning: policy.protectedBranches names no usable branch; using ${DEFAULT_PROTECTED_BRANCHES.join(", ")}`);
    return [...DEFAULT_PROTECTED_BRANCHES];
  }
  return [...new Set(out)];
}

/** Only two model steps exist; anything else is a typo, and a typo must not silently pick one. */
function validProvider(p: string): "jev" | "openai" {
  if (p === "jev" || p === "openai") return p;
  console.error(`[auto-classifier] Warning: unknown llm.provider "${p}"; using "jev"`);
  return "jev";
}

/** `overlay: false` skips the machine-local overlay; the bench uses it to certify the shipped defaults on any machine. */
export function loadConfig(explicitPath?: string, opts: { overlay?: boolean } = {}): AppConfig {
  // The file AUTO_CLASSIFIER_CONFIG names is the gate's config even before it
  // exists: an agent that created it would choose the gate's model and rules.
  if (process.env.AUTO_CLASSIFIER_CONFIG) protectGateFile(path.resolve(process.env.AUTO_CLASSIFIER_CONFIG));
  const configPath = findConfigFile(explicitPath);
  if (configPath) protectGateFile(path.resolve(configPath));
  let fileConfig: Partial<AppConfig> = {};

  if (configPath) {
    try {
      const raw = fs.readFileSync(configPath, "utf-8");
      fileConfig = parseJsonc<Partial<AppConfig>>(raw);
    } catch (err) {
      console.error(`[auto-classifier] Warning: failed to parse config file at ${configPath}:`, err);
    }
  }

  // Machine-local overlay: same shape as the shared config file, merged over it
  // (deep for objects, replacing for arrays/scalars) before env vars apply.
  // Precedence end to end: env > local overlay > config file > defaults.
  const overlayPath = opts.overlay === false ? null : findLocalOverlayFile();
  if (overlayPath) {
    try {
      const raw = fs.readFileSync(overlayPath, "utf-8");
      const overlay = parseJsonc<Partial<AppConfig>>(raw);
      fileConfig = deepMerge(fileConfig, overlay);
    } catch (err) {
      console.error(`[auto-classifier] Warning: failed to parse local overlay at ${overlayPath}:`, err);
    }
  }

  const rawApiKey =
    process.env.AUTO_CLASSIFIER_API_KEY ||
    process.env.OPENAI_API_KEY ||
    fileConfig.llm?.apiKey ||
    readApiKeyFile(fileConfig.llm?.apiKeyFile) ||
    "";

  const resolvedApiKey = resolveApiKey(rawApiKey);

  const baseUrl =
    process.env.AUTO_CLASSIFIER_BASE_URL ||
    process.env.OPENAI_BASE_URL ||
    fileConfig.llm?.baseUrl ||
    "https://openrouter.ai/api/v1";

  const model =
    process.env.AUTO_CLASSIFIER_MODEL ||
    fileConfig.llm?.model ||
    "deepseek/deepseek-v4.1-flash";

  const fallbackModel =
    process.env.AUTO_CLASSIFIER_FALLBACK_MODEL ||
    fileConfig.llm?.fallbackModel ||
    undefined;

  // Further fallback tiers, tried in order after `fallbackModel`. Unset by
  // default -- today's single-fallback behaviour is unchanged until a config
  // or the env var opts into a longer chain.
  const fallbackModelsRaw =
    process.env.AUTO_CLASSIFIER_FALLBACK_MODELS ??
    (fileConfig.llm?.fallbackModels ? fileConfig.llm.fallbackModels.join(",") : undefined);
  const fallbackModels = fallbackModelsRaw
    ? fallbackModelsRaw.split(",").map((m) => m.trim()).filter(Boolean)
    : [];

  // Optional cheaper first pass: its allow is final, its deny or parse failure
  // is re-asked of `model`. Unset by default.
  const triageModel = process.env.AUTO_CLASSIFIER_TRIAGE_MODEL || fileConfig.llm?.triageModel || undefined;

  const maxTokens = fileConfig.llm?.maxTokens ?? 120;

  const extraBody = fileConfig.llm?.extraBody;

  const timeoutMs =
    (process.env.AUTO_CLASSIFIER_TIMEOUT_MS ? parseInt(process.env.AUTO_CLASSIFIER_TIMEOUT_MS, 10) : 0) ||
    fileConfig.llm?.timeoutMs ||
    15000;

  // The whole model chain's deadline, kept under the 20 s agy gives a hook so
  // the gate answers (with a deny) before the harness gives up on it.
  const totalTimeoutMs =
    (process.env.AUTO_CLASSIFIER_TOTAL_TIMEOUT_MS ? parseInt(process.env.AUTO_CLASSIFIER_TOTAL_TIMEOUT_MS, 10) : 0) ||
    fileConfig.llm?.totalTimeoutMs ||
    18000;

  const denyMode = (process.env.AUTO_CLASSIFIER_DENY_MODE ||
    fileConfig.policy?.denyMode ||
    "both") as "both" | "auto-retry" | "ask-user";

  const consecutiveThreshold = fileConfig.policy?.consecutiveThreshold ?? 2;

  const slidingWindowMs =
    fileConfig.policy?.slidingWindowMs ?? 300000; // 5 minutes

  const instructAgentOnDenial =
    fileConfig.policy?.instructAgentOnDenial ?? true;

  const maxFileChars = fileConfig.llm?.maxFileChars ?? 2000;

  const trustLandedScripts = fileConfig.policy?.trustLandedScripts ?? true;

  const escalationTimeoutMinutes =
    (process.env.AUTO_CLASSIFIER_TIMEOUT_MINUTES ? parseInt(process.env.AUTO_CLASSIFIER_TIMEOUT_MINUTES, 10) : 0) ||
    fileConfig.policy?.escalationTimeoutMinutes ||
    5;

  const headless = process.env.AUTO_CLASSIFIER_HEADLESS
    ? /^(1|true|yes)$/i.test(process.env.AUTO_CLASSIFIER_HEADLESS)
    : fileConfig.policy?.headless ?? false;

  const protectedBranches = readProtectedBranches(fileConfig.policy?.protectedBranches);

  const fastDeny = fileConfig.rules?.fastDeny || [
    "^\\s*mkfs(\\.[a-z0-9]+)?\\s+",
    "^\\s*dd\\s+.*of=\\/dev\\/(sd[a-z]|nvme[0-9]n[0-9]|vd[a-z])",
    ":\\(\\)\\s*\\{\\s*:\\s*\\|\\s*:\\s*&\\s*\\};\\s*:",
  ];

  const fastAllow = fileConfig.rules?.fastAllow || [
    "^\\s*(?:\\$[a-zA-Z0-9_]+\\s*=\\s*)?(?:Get-ChildItem|Get-Content|Get-Item|Get-Process|Get-Service|Select-String|Test-Path|Format-List|Format-Table|ConvertFrom-Json|ConvertTo-Json)\\b",
    // Every rule names the verbs it vouches for. Most are reads; the local
    // git writes (add, commit) and a plain push to a non-trunk branch are the
    // exceptions, and the upload check has already vetted a push's remote. A
    // blanket `\b` after a tool name would vouch for every verb it has,
    // including its deletes and merges.
    "^\\s*git\\s+(?:-c\\s+[^;&|]+?\\s+)*(?:status|diff|log|show|grep|rev-parse|ls-files|cherry|merge-base|commit|add)\\b",
    "^\\s*git\\s+worktree\\s+list\\b",
    // git branch is read-only ONLY in these exact list-shaped forms -- no
    // -D/-d/-f/-m/-M/--delete/--force; anything else defers to the model.
    "^\\s*git\\s+branch(?:\\s+(?:-a|-r|-v|-vv|--list|--all|--remotes|--show-current|--verbose))*\\s*$",
    "^\\s*git\\s+remote(?:\\s+(?:-v|show\\s+\\S+|get-url\\s+\\S+))?\\s*$",
    // A plain fetch only updates remote-tracking refs; a refspec (`+main:main`)
    // does not match and goes to the model.
    "^\\s*git\\s+fetch(?:\\s+(?:--all|--dry-run|--prune))?(?:\\s+[a-zA-Z0-9_.\\/-]+)?\\s*$",
    // A plain push to any branch but a protected one (policy.protectedBranches).
    pushFastAllowRule(protectedBranches),
    // `gh pr merge` is deliberately absent: it is a write that can land a
    // change or bypass branch protection (`--admin`), never a fast rule's
    // call to make.
    "^\\s*gh\\s+(?:issue\\s+(?:view|list|status)|pr\\s+(?:view|list|diff|checks|status)|run\\s+(?:list|view)|release\\s+(?:list|view)|label\\s+list|repo\\s+view)\\b",
    "^\\s*systemctl\\s+(?:status|is-active|is-enabled|is-failed|list-units|list-timers|show|cat)\\b",
    "^\\s*journalctl\\b",
    "^\\s*ls(\\s+-[a-zA-Z0-9]+)*(\\s+[^\\s;&|]+)?$",
    "^\\s*pwd$",
    "^\\s*whoami$",
    "^\\s*cargo\\s+(check|clippy)$",
    "^\\s*(?:python3?\\s+-m\\s+)?pytest(\\s+[^;&|]+)?$",
    "^\\s*npm\\s+test\\b",
    "^\\s*rg\\b",
  ];

  const scratchWriteRoots = fileConfig.rules?.scratchWriteRoots || ["/tmp/"];

  const telemetryRaw = (fileConfig as Record<string, any>).telemetry ?? {};
  const telemetry = {
    enabled: telemetryRaw.enabled ?? true,
    path: typeof telemetryRaw.path === "string" ? telemetryRaw.path : "",
    maxBytes: typeof telemetryRaw.maxBytes === "number" && telemetryRaw.maxBytes >= 0 ? telemetryRaw.maxBytes : DEFAULT_TELEMETRY_MAX_BYTES,
  };

  const jevRaw: Partial<JevConfig> = (fileConfig as Record<string, any>).jev ?? {};
  const jevCommandEnv = process.env.AUTO_CLASSIFIER_JEV_COMMAND;
  const parseCommand = (raw: string): string[] | undefined => {
    try {
      const v = JSON.parse(raw);
      if (Array.isArray(v) && v.length > 0 && v.every((x) => typeof x === "string")) return v;
    } catch {
      // fall through
    }
    console.error("[auto-classifier] Warning: AUTO_CLASSIFIER_JEV_COMMAND must be a JSON array of strings; ignoring it");
    return undefined;
  };
  // A threshold outside [0, 1] would switch a check off; clamp and say so.
  const unit = (name: string, v: unknown, fallback: number): number => {
    if (typeof v !== "number" || Number.isNaN(v)) return fallback;
    if (v < 0 || v > 1) console.error(`[auto-classifier] Warning: jev.${name} ${v} is outside [0, 1]; clamping`);
    return Math.min(1, Math.max(0, v));
  };
  const instructionsAppend =
    typeof fileConfig.policy?.instructionsAppend === "string"
      ? fileConfig.policy.instructionsAppend
      : typeof (fileConfig as any).instructionsAppend === "string"
      ? (fileConfig as any).instructionsAppend
      : process.env.AUTO_CLASSIFIER_INSTRUCTIONS_APPEND || undefined;

  const jev: JevConfig = {
    baseUrl: process.env.TYPESAFE_BASE_URL || jevRaw.baseUrl || "https://api.typesafe.ai",
    apiKey: resolveApiKey(process.env.TYPESAFE_API_KEY || jevRaw.apiKey || "") || undefined,
    command: jevCommandEnv ? parseCommand(jevCommandEnv) : jevRaw.command,
    model: process.env.AUTO_CLASSIFIER_JEV_MODEL || jevRaw.model || "jev-1.13.0",
    riskThreshold: unit("riskThreshold", jevRaw.riskThreshold, 0.7),
    minConfidence: unit("minConfidence", jevRaw.minConfidence, 0.6),
    lowRiskCeiling: unit("lowRiskCeiling", jevRaw.lowRiskCeiling, 0.2),
    lowRiskMinAllow: unit("lowRiskMinAllow", jevRaw.lowRiskMinAllow, 0.6),
    timeoutMs: jevRaw.timeoutMs ?? 10000,
    instructionsAppend: jevRaw.instructionsAppend ?? instructionsAppend,
  };
  const sanctionedRemotes = loadSanctionedRemotes(fileConfig as Record<string, any>);
  jev.sanctionedRemotes = sanctionedRemotes;
  jev.protectedBranches = protectedBranches;

  return {
    sanctionedRemotes,
    jev,
    llm: {
      provider: validProvider(process.env.AUTO_CLASSIFIER_PROVIDER || fileConfig.llm?.provider || "jev"),
      baseUrl,
      apiKey: resolvedApiKey,
      model,
      fallbackModel,
      fallbackModels,
      triageModel,
      timeoutMs,
      totalTimeoutMs,
      maxFileChars,
      maxTokens,
      extraBody,
      instructionsAppend: fileConfig.llm?.instructionsAppend ?? instructionsAppend,
      sanctionedRemotes,
      protectedBranches,
    },
    policy: {
      denyMode,
      consecutiveThreshold,
      slidingWindowMs,
      instructAgentOnDenial,
      headless,
      trustLandedScripts,
      escalationTimeoutMinutes,
      instructionsAppend,
      protectedBranches,
    },
    rules: {
      fastDeny,
      fastAllow,
      scratchWriteRoots,
    },
    telemetry,
    agy: {
      autoAcceptInTmux: (fileConfig as Record<string, any>).agy?.autoAcceptInTmux === true,
      alwaysProceedEscalations: readAlwaysProceedEscalations((fileConfig as Record<string, any>).agy?.alwaysProceedEscalations),
    },
  };
}
