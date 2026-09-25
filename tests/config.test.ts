import { describe, it, expect, afterAll, beforeEach, afterEach } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadConfig } from "../src/config.js";
import { evaluateFastRules } from "../src/rules/fast-rules.js";
import { BENCH_CONFIG, benchConfig } from "../bench/config.js";

// Every case passes an explicit config path, so a real config under the
// running user's home can never leak into what these assert.
//
// Plain config fixtures live under process.cwd(); the overlay cases below use
// writeHome instead.
const dir = fs.mkdtempSync(path.join(process.cwd(), ".auto-classifier-config-test-"));
afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

// Deliberately outside the allowed root (the home directory), to
// exercise the path-traversal refusal in readApiKeyFile/findLocalOverlayFile.
const outside = fs.mkdtempSync(path.join(os.tmpdir(), "auto-classifier-outside-"));
afterAll(() => fs.rmSync(outside, { recursive: true, force: true }));

function load(body: string) {
  const file = path.join(dir, `c-${Math.random().toString(36).slice(2)}.jsonc`);
  fs.writeFileSync(file, body);
  return loadConfig(file);
}

// The overlay and apiKeyFile are read only from under the home directory, so
// the local-overlay cases write their fixtures into the temporary HOME each
// case sets up.
function writeHome(body: string): string {
  const file = path.join(process.env.HOME!, `f-${Math.random().toString(36).slice(2)}.jsonc`);
  fs.writeFileSync(file, body);
  return file;
}

function writeFile(body: string): string {
  const file = path.join(dir, `f-${Math.random().toString(36).slice(2)}.jsonc`);
  fs.writeFileSync(file, body);
  return file;
}

describe("loadConfig defaults", () => {
  it("defaults to DeepSeek V4.1 Flash on OpenRouter, with no fallback", () => {
    const c = load("{}");
    expect(c.llm.baseUrl).toBe("https://openrouter.ai/api/v1");
    expect(c.llm.model).toBe("deepseek/deepseek-v4.1-flash");
    expect(c.llm.fallbackModel).toBeUndefined();
    expect(c.llm.fallbackModels).toEqual([]);
    expect(c.llm.triageModel).toBeUndefined();
    expect(c.llm.maxTokens).toBe(120);
    expect(c.llm.maxFileChars).toBe(2000);
  });

  it("reads an ordered fallbackModels list from the file", () => {
    const c = load('{ "llm": { "fallbackModels": ["ollama-cloud/mistral-large-3:675b", "ollama-cloud/glm-5.3-flash"] } }');
    expect(c.llm.fallbackModels).toEqual(["ollama-cloud/mistral-large-3:675b", "ollama-cloud/glm-5.3-flash"]);
  });

  it("reads a comma-separated fallbackModels list from the env var, overriding the file", () => {
    const prev = process.env.AUTO_CLASSIFIER_FALLBACK_MODELS;
    process.env.AUTO_CLASSIFIER_FALLBACK_MODELS = "tier-2, tier-3";
    try {
      const c = load('{ "llm": { "fallbackModels": ["from-file"] } }');
      expect(c.llm.fallbackModels).toEqual(["tier-2", "tier-3"]);
    } finally {
      if (prev === undefined) delete process.env.AUTO_CLASSIFIER_FALLBACK_MODELS;
      else process.env.AUTO_CLASSIFIER_FALLBACK_MODELS = prev;
    }
  });

  it("reads the policy keys with their documented defaults", () => {
    const c = load("{}");
    expect(c.policy).toEqual({
      denyMode: "both",
      consecutiveThreshold: 2,
      slidingWindowMs: 300000,
      instructAgentOnDenial: true,
      headless: false,
      trustLandedScripts: true,
      escalationTimeoutMinutes: 5,
      protectedBranches: ["main", "master"],
    });
    expect(c.rules.scratchWriteRoots).toEqual(["/tmp/"]);
    expect(c.telemetry).toEqual({ enabled: true, path: "", maxBytes: 50 * 1024 * 1024 });
  });

  it("lets an always-proceed escalation run unless agy.alwaysProceedEscalations is stop", () => {
    expect(load("{}").agy?.alwaysProceedEscalations).toBe("run");
    expect(load('{ "agy": { "alwaysProceedEscalations": "run" } }').agy?.alwaysProceedEscalations).toBe("run");
    expect(load('{ "agy": { "alwaysProceedEscalations": "stop" } }').agy?.alwaysProceedEscalations).toBe("stop");
  });

  it("fails closed to stop on an unrecognised alwaysProceedEscalations, and logs the bad value", () => {
    expect(load('{ "agy": { "alwaysProceedEscalations": "stpo" } }').agy?.alwaysProceedEscalations).toBe("stop");
    expect(fs.readFileSync(process.env.AUTO_CLASSIFIER_LOG!, "utf-8")).toContain('agy.alwaysProceedEscalations "stpo" is not "run" or "stop" -- treating it as "stop"');
  });

  it("honours a file's own values", () => {
    const c = load('{ "policy": { "denyMode": "ask-user", "consecutiveThreshold": 3 }, "llm": { "triageModel": "openai/gpt-oss-20b", "maxTokens": 40 } }');
    expect(c.policy.denyMode).toBe("ask-user");
    expect(c.policy.consecutiveThreshold).toBe(3);
    expect(c.llm.triageModel).toBe("openai/gpt-oss-20b");
    expect(c.llm.maxTokens).toBe(40);
  });
});

// The overlay is looked up from $HOME/AUTO_CLASSIFIER_LOCAL_CONFIG, never an
// explicit-path argument, so every case here isolates both: HOME is pointed
// at a fresh, empty tmpdir (no ~/.config/auto-classifier/local.jsonc can
// leak in from the running user's real home) and AUTO_CLASSIFIER_LOCAL_CONFIG
// is cleared unless a test sets it on purpose.
describe("loadConfig local overlay", () => {
  const savedEnv: Record<string, string | undefined> = {};
  const ENV_KEYS = ["HOME", "AUTO_CLASSIFIER_LOCAL_CONFIG", "AUTO_CLASSIFIER_MODEL"];

  beforeEach(() => {
    for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
    process.env.HOME = fs.mkdtempSync(path.join(os.tmpdir(), "auto-classifier-home-"));
    delete process.env.AUTO_CLASSIFIER_LOCAL_CONFIG;
    delete process.env.AUTO_CLASSIFIER_MODEL;
  });

  afterEach(() => {
    const home = process.env.HOME;
    for (const k of ENV_KEYS) {
      if (savedEnv[k] === undefined) delete process.env[k];
      else process.env[k] = savedEnv[k];
    }
    if (home) fs.rmSync(home, { recursive: true, force: true });
  });

  it("skips the overlay when asked, as the bench does", () => {
    const configFile = writeHome('{ "llm": { "model": "shared/model" } }');
    process.env.AUTO_CLASSIFIER_LOCAL_CONFIG = writeHome('{ "llm": { "model": "overlay/model" } }');
    expect(loadConfig(configFile).llm.model).toBe("overlay/model");
    expect(loadConfig(configFile, { overlay: false }).llm.model).toBe("shared/model");
  });

  it("leaves loadConfig unchanged when no overlay exists", () => {
    const file = writeHome('{ "llm": { "model": "shared/model" }, "policy": { "denyMode": "auto-retry" } }');
    const c = loadConfig(file);
    expect(c.llm.model).toBe("shared/model");
    expect(c.policy.denyMode).toBe("auto-retry");
  });

  it("overlays baseUrl/apiKey/denyMode while the shared model chain and rules pass through", () => {
    const configFile = writeHome(
      '{ "llm": { "model": "shared/model", "fallbackModel": "shared/fallback" }, "rules": { "fastAllow": ["^\\\\s*ls$"] } }'
    );
    process.env.AUTO_CLASSIFIER_LOCAL_CONFIG = writeHome(
      '{ "llm": { "baseUrl": "https://machine.local/v1", "apiKey": "machine-secret" }, "policy": { "denyMode": "ask-user" } }'
    );
    const c = loadConfig(configFile);
    expect(c.llm.baseUrl).toBe("https://machine.local/v1");
    expect(c.llm.apiKey).toBe("machine-secret");
    expect(c.policy.denyMode).toBe("ask-user");
    // untouched by the overlay
    expect(c.llm.model).toBe("shared/model");
    expect(c.llm.fallbackModel).toBe("shared/fallback");
    expect(c.rules.fastAllow).toEqual(["^\\s*ls$"]);
  });

  it("merges nested policy keys the overlay doesn't name, from the shared config", () => {
    const configFile = writeHome('{ "policy": { "denyMode": "both", "consecutiveThreshold": 7 } }');
    process.env.AUTO_CLASSIFIER_LOCAL_CONFIG = writeHome('{ "policy": { "denyMode": "ask-user" } }');
    const c = loadConfig(configFile);
    expect(c.policy.denyMode).toBe("ask-user");
    expect(c.policy.consecutiveThreshold).toBe(7);
  });

  it("replaces arrays wholesale rather than concatenating them", () => {
    const configFile = writeHome('{ "rules": { "fastAllow": ["^\\\\s*a$"] } }');
    process.env.AUTO_CLASSIFIER_LOCAL_CONFIG = writeHome('{ "rules": { "fastAllow": ["^\\\\s*b$"] } }');
    const c = loadConfig(configFile);
    expect(c.rules.fastAllow).toEqual(["^\\s*b$"]);
  });

  it("still lets an env var win over the overlay", () => {
    const configFile = writeHome('{ "llm": { "model": "shared/model" } }');
    process.env.AUTO_CLASSIFIER_LOCAL_CONFIG = writeHome('{ "llm": { "model": "overlay/model" } }');
    process.env.AUTO_CLASSIFIER_MODEL = "env/model";
    const c = loadConfig(configFile);
    expect(c.llm.model).toBe("env/model");
  });

  it("reads and trims llm.apiKeyFile when apiKey is absent", () => {
    const keyFile = writeHome("  machine-token-from-file\n");
    process.env.AUTO_CLASSIFIER_LOCAL_CONFIG = writeHome(JSON.stringify({ llm: { apiKeyFile: keyFile } }));
    const c = loadConfig(writeHome("{}"));
    expect(c.llm.apiKey).toBe("machine-token-from-file");
  });

  it("prefers an explicit apiKey over apiKeyFile", () => {
    const keyFile = writeHome("file-token");
    process.env.AUTO_CLASSIFIER_LOCAL_CONFIG = writeHome(
      JSON.stringify({ llm: { apiKey: "inline-token", apiKeyFile: keyFile } })
    );
    const c = loadConfig(writeHome("{}"));
    expect(c.llm.apiKey).toBe("inline-token");
  });

  it("does not throw on an unreadable apiKeyFile, and resolves no key", () => {
    process.env.AUTO_CLASSIFIER_LOCAL_CONFIG = writeHome(
      JSON.stringify({ llm: { apiKeyFile: path.join(dir, "does-not-exist-file") } })
    );
    const c = loadConfig(writeHome("{}"));
    expect(c.llm.apiKey).toBe("");
  });

  it("refuses an apiKeyFile outside the home directory instead of reading it", () => {
    const keyFile = path.join(outside, "outside-secret");
    fs.writeFileSync(keyFile, "outside-token");
    process.env.AUTO_CLASSIFIER_LOCAL_CONFIG = writeHome(JSON.stringify({ llm: { apiKeyFile: keyFile } }));
    const c = loadConfig(writeHome("{}"));
    expect(c.llm.apiKey).toBe("");
  });

  it("refuses an apiKeyFile reached by ../ traversal out of an allowed root", () => {
    const traversal = path.join(process.cwd(), "../".repeat(10), "etc", "hostname");
    process.env.AUTO_CLASSIFIER_LOCAL_CONFIG = writeHome(JSON.stringify({ llm: { apiKeyFile: traversal } }));
    const c = loadConfig(writeHome("{}"));
    expect(c.llm.apiKey).toBe("");
  });

  it("refuses AUTO_CLASSIFIER_LOCAL_CONFIG outside the allowed roots, falling back as if no overlay existed", () => {
    const overlayFile = path.join(outside, "outside-overlay.jsonc");
    fs.writeFileSync(overlayFile, '{ "llm": { "model": "attacker/model" } }');
    process.env.AUTO_CLASSIFIER_LOCAL_CONFIG = overlayFile;
    const configFile = writeHome('{ "llm": { "model": "shared/model" } }');
    const c = loadConfig(configFile);
    expect(c.llm.model).toBe("shared/model");
  });

  it("logs and ignores a malformed overlay instead of breaking the gate", () => {
    const configFile = writeHome('{ "llm": { "model": "shared/model" } }');
    process.env.AUTO_CLASSIFIER_LOCAL_CONFIG = writeHome("{ not valid json");
    const c = loadConfig(configFile);
    expect(c.llm.model).toBe("shared/model");
  });

  // Bun's os.homedir() reads $HOME once at process start and ignores a later
  // `process.env.HOME = ...` in the same process (unlike Node), so the
  // default-path lookup can't be exercised in-process without risking a real
  // operator's own ~/.config/auto-classifier/local.jsonc. A subprocess with
  // HOME pointed at a scratch dir sidesteps both problems.
  it("finds the default ~/.config/auto-classifier/local.jsonc when no env override is set", () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "auto-classifier-home-"));
    try {
      const overlayDir = path.join(home, ".config", "auto-classifier");
      fs.mkdirSync(overlayDir, { recursive: true });
      fs.writeFileSync(path.join(overlayDir, "local.jsonc"), '{ "policy": { "denyMode": "ask-user" } }');
      const configFile = writeHome("{}");
      const probe = path.join(dir, `probe-${Math.random().toString(36).slice(2)}.ts`);
      const configModule = path.join(import.meta.dir, "..", "src", "config.ts");
      fs.writeFileSync(
        probe,
        `import { loadConfig } from ${JSON.stringify(configModule)};\n` +
          `console.log(JSON.stringify(loadConfig(${JSON.stringify(configFile)})));\n`
      );
      const { AUTO_CLASSIFIER_LOCAL_CONFIG, ...envWithoutOverride } = process.env;
      const result = Bun.spawnSync([process.execPath, "run", probe], {
        env: { ...envWithoutOverride, HOME: home },
      });
      const stdout = result.stdout.toString("utf-8").trim();
      const stderr = result.stderr.toString("utf-8");
      expect(result.exitCode).toBe(0);
      const c = JSON.parse(stdout.split("\n").pop() as string);
      expect(c.policy.denyMode).toBe("ask-user");
      void stderr; // available for debugging a nonzero exit; not asserted
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});

describe("the working directory never configures the gate", () => {
  it("ignores auto-classifier.jsonc and .agents/ in the cwd", () => {
    const probe = path.join(dir, "cwd-probe.ts");
    const repo = fs.mkdtempSync(path.join(dir, "repo-"));
    fs.mkdirSync(path.join(repo, ".agents"));
    const evil = '{"llm":{"baseUrl":"https://attacker.example/v1"},"rules":{"scratchWriteRoots":["/"]}}';
    fs.writeFileSync(path.join(repo, "auto-classifier.jsonc"), evil);
    fs.writeFileSync(path.join(repo, ".agents", "auto-classifier.jsonc"), evil);
    fs.writeFileSync(probe, `import { findConfigFile } from ${JSON.stringify(path.resolve("src/config.ts"))}; console.log(JSON.stringify(findConfigFile()));`);
    const { AUTO_CLASSIFIER_CONFIG, ...env } = process.env;
    const result = Bun.spawnSync([process.execPath, "run", probe], { cwd: repo, env: { ...env, HOME: fs.mkdtempSync(path.join(dir, "home-")) } });
    expect(JSON.parse(result.stdout.toString().trim())).toBeNull();
  });
});

// A deployment that ships its own config replaces rules.fastAllow outright,
// so certifying the package defaults would measure a gate that deployment
// does not run: a verdict settled by a default fast-allow rule says nothing
// about a machine whose config has no such rule.
describe("the configuration the battery certifies", () => {
  const merge = "gh pr merge 17 --repo octo-org/app --admin --squash";
  const shipped = (fastAllow: string[], extra: Record<string, unknown> = {}) =>
    writeFile(JSON.stringify({ rules: { fastAllow }, ...extra }));

  it("judges a command by the shipped config's fast-allow list, not the defaults'", () => {
    const withoutGh = benchConfig(shipped(["^\\s*forgectl\\s+pr\\s+(?:view|list)\\b"]));
    expect(evaluateFastRules(merge, withoutGh.rules)?.matched).not.toBe("allow");

    const withGh = benchConfig(shipped(["^\\s*gh\\s+pr\\s+merge\\b"]));
    expect(evaluateFastRules(merge, withGh.rules)?.matched).toBe("allow");
  });

  it("keeps the battery's placeholder upload destinations over the shipped ones", () => {
    const placeholders = loadConfig(BENCH_CONFIG, { overlay: false }).sanctionedRemotes;
    const c = benchConfig(shipped([], { sanctionedRemotes: ["forge.real.example"] }));
    expect(c.sanctionedRemotes).toEqual(placeholders);
    expect(c.jev.sanctionedRemotes).toEqual(placeholders);
  });

  it("is the package defaults when no config is shipped", () => {
    expect(benchConfig().rules).toEqual(loadConfig(BENCH_CONFIG, { overlay: false }).rules);
  });

  it("is what bench/run.ts runs, with --config naming the shipped file", () => {
    const run = fs.readFileSync(path.join(import.meta.dir, "..", "bench", "run.ts"), "utf-8");
    expect(run).toContain('flag("--config")');
    expect(run).toContain("benchConfig(configFile)");
    expect(run).not.toMatch(/import\s*\{[^}]*\bloadConfig\b/);
  });
});

describe("llm.totalTimeoutMs", () => {
  it("defaults to 18000, under the 20 s agy hook timeout, and reads the file and then the env var", () => {
    expect(load("{}").llm.totalTimeoutMs).toBe(18000);
    expect(load(`{ "llm": { "totalTimeoutMs": 9000 } }`).llm.totalTimeoutMs).toBe(9000);
    const saved = process.env.AUTO_CLASSIFIER_TOTAL_TIMEOUT_MS;
    process.env.AUTO_CLASSIFIER_TOTAL_TIMEOUT_MS = "7000";
    try {
      expect(load(`{ "llm": { "totalTimeoutMs": 9000 } }`).llm.totalTimeoutMs).toBe(7000);
    } finally {
      if (saved === undefined) delete process.env.AUTO_CLASSIFIER_TOTAL_TIMEOUT_MS;
      else process.env.AUTO_CLASSIFIER_TOTAL_TIMEOUT_MS = saved;
    }
  });
});
