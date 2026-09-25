import { afterEach, beforeEach, describe, expect, it, spyOn } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadConfig } from "../src/config.js";
import { logPath } from "../src/log.js";
import { telemetryPath } from "../src/telemetry.js";
import { getTimeoutFilePath } from "../src/adapters/agy-accept.js";
import { isGatePath, selfProtectionDenial } from "../src/rules/self-protection.js";
import { analyzeCommand } from "../src/rules/command-shape.js";
import { judgeFileWrite } from "../src/rules/file-write.js";

/**
 * One directory holds the gate's config, overlay, log, telemetry and timeout
 * records: ~/.config/auto-classifier. Every reader resolves it the same way,
 * so what self-protection guards is where the gate actually keeps its files.
 * A config file named by AUTO_CLASSIFIER_CONFIG (or the overlay's variable),
 * and a sanctionedRemotesFile, can live anywhere; each is a gate file too.
 */
const KEYS = ["HOME", "XDG_CONFIG_HOME", "AUTO_CLASSIFIER_LOG", "AUTO_CLASSIFIER_STATE_DIR", "AUTO_CLASSIFIER_CONFIG", "AUTO_CLASSIFIER_LOCAL_CONFIG"];
let saved: Record<string, string | undefined> = {};
let home = "";

beforeEach(() => {
  saved = Object.fromEntries(KEYS.map((k) => [k, process.env[k]]));
  home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "auto-classifier-gate-paths-")));
  process.env.HOME = home;
  for (const k of KEYS.slice(1)) delete process.env[k];
});

afterEach(() => {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

describe("one directory for every gate file", () => {
  it("the log, telemetry and timeout records sit beside the config, whatever XDG_CONFIG_HOME says", () => {
    process.env.XDG_CONFIG_HOME = path.join(home, "elsewhere");
    const dir = path.join(home, ".config", "auto-classifier");
    expect(logPath()).toBe(path.join(dir, "auto-classifier.log"));
    expect(telemetryPath({ enabled: true, path: "" })).toBe(path.join(dir, "telemetry.jsonl"));
    expect(getTimeoutFilePath("s1")).toBe(path.join(dir, "timeouts", "s1.json"));
  });
});

describe("configured gate files are protected", () => {
  it("the file AUTO_CLASSIFIER_CONFIG names, and the sanctionedRemotesFile it names, are gate files", () => {
    const cfgDir = path.join(home, "dotfiles");
    fs.mkdirSync(cfgDir);
    const cfg = path.join(cfgDir, "gate.jsonc");
    const remotes = path.join(cfgDir, "remotes.json");
    fs.writeFileSync(cfg, JSON.stringify({ sanctionedRemotesFile: remotes }));
    fs.writeFileSync(remotes, JSON.stringify(["forge.example.ts.net"]));
    process.env.AUTO_CLASSIFIER_CONFIG = cfg;
    loadConfig();
    for (const p of [cfg, remotes]) {
      expect(isGatePath(p)).toBe(true);
      expect(selfProtectionDenial(analyzeCommand(`echo x > ${p}`))).not.toBeNull();
      expect(selfProtectionDenial(analyzeCommand(`rm -f ${p}`))).not.toBeNull();
      expect(judgeFileWrite(p, [cfgDir]).decision).toBe("deny");
    }
    // A relative spelling from the directory it is in.
    expect(isGatePath("gate.jsonc", cfgDir)).toBe(true);
    // Its neighbours are not.
    expect(isGatePath(path.join(cfgDir, "other.jsonc"))).toBe(false);
  });

  it("an AUTO_CLASSIFIER_CONFIG path that does not exist yet is protected, so the agent cannot create it", () => {
    const cfg = path.join(home, "not-yet.jsonc");
    process.env.AUTO_CLASSIFIER_CONFIG = cfg;
    loadConfig();
    expect(isGatePath(cfg)).toBe(true);
  });

  it("the overlay AUTO_CLASSIFIER_LOCAL_CONFIG names is a gate file", () => {
    const overlay = path.join(home, "machine.jsonc");
    fs.writeFileSync(overlay, "{}");
    process.env.AUTO_CLASSIFIER_LOCAL_CONFIG = overlay;
    loadConfig();
    expect(isGatePath(overlay)).toBe(true);
  });
});

describe("a missing AUTO_CLASSIFIER_CONFIG", () => {
  it("is warned about on stderr, not silently replaced by the default config", () => {
    const missing = path.join(home, "typo.jsonc");
    process.env.AUTO_CLASSIFIER_CONFIG = missing;
    const spy = spyOn(console, "error").mockImplementation(() => {});
    try {
      loadConfig();
      const said = spy.mock.calls.map((c) => c.join(" ")).join("\n");
      expect(said).toContain("AUTO_CLASSIFIER_CONFIG");
      expect(said).toContain(missing);
    } finally {
      spy.mockRestore();
    }
  });
});
