import { describe, it, expect, spyOn } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { appendCapped } from "../src/capped-append.js";
import { DEFAULT_TELEMETRY_MAX_BYTES, writeTelemetry } from "../src/telemetry.js";
import { LOG_MAX_BYTES, log } from "../src/log.js";
import { loadConfig } from "../src/config.js";
import { tmpStateDir } from "./helpers/tmp-state.js";

/**
 * telemetry.jsonl and auto-classifier.log grow by a line per decision, so each
 * is capped: a write that would take the file past its cap first moves it to
 * `<file>.1` (replacing any older one), and the line starts a fresh file.
 */
const row = (command: string) => ({
  id: "",
  session: "s",
  command,
  file_path: null,
  file_snippet: null,
  decision: "allow" as const,
  source: "fast-allow",
  reason: "",
  latency_ms: 0,
  model: null,
  injection_attempt: false,
  injection_pattern: null,
  cwd: null,
});

describe("appendCapped", () => {
  it("keeps the file under its cap, with one predecessor, and loses no line to a split", () => {
    const file = path.join(tmpStateDir(), "t.jsonl");
    for (let i = 0; i < 100; i++) appendCapped(file, `line ${String(i).padStart(3, "0")}\n`, 100);
    expect(fs.statSync(file).size).toBeLessThanOrEqual(100);
    expect(fs.existsSync(`${file}.1`)).toBe(true);
    expect(fs.statSync(`${file}.1`).size).toBeLessThanOrEqual(100);
    expect(fs.existsSync(`${file}.2`)).toBe(false);
    const lines = [...fs.readFileSync(`${file}.1`, "utf-8").split("\n"), ...fs.readFileSync(file, "utf-8").split("\n")].filter(Boolean);
    expect(lines.every((l) => /^line \d{3}$/.test(l))).toBe(true);
    expect(lines[lines.length - 1]).toBe("line 099");
  });

  it("a cap of 0 never rotates", () => {
    const file = path.join(tmpStateDir(), "t.jsonl");
    for (let i = 0; i < 50; i++) appendCapped(file, "0123456789\n", 0);
    expect(fs.statSync(file).size).toBe(550);
    expect(fs.existsSync(`${file}.1`)).toBe(false);
  });

  it("a single line longer than the cap is still written", () => {
    const file = path.join(tmpStateDir(), "t.jsonl");
    appendCapped(file, "short\n", 10);
    appendCapped(file, "a line far longer than the cap\n", 10);
    expect(fs.readFileSync(file, "utf-8")).toBe("a line far longer than the cap\n");
    expect(fs.readFileSync(`${file}.1`, "utf-8")).toBe("short\n");
  });
});

/** A rename that fails the way the filesystem would, with `code` set. */
function failingRename(code: string, onCall: () => void = () => {}) {
  return spyOn(fs, "renameSync").mockImplementation(() => {
    onCall();
    throw Object.assign(new Error(`${code}: rename refused`), { code });
  });
}

describe("appendCapped when the rotation's rename fails", () => {
  it("another writer rotated first (ENOENT): the line is appended to the fresh file, not dropped", () => {
    const file = path.join(tmpStateDir(), "t.jsonl");
    fs.writeFileSync(file, "x".repeat(97) + "\n");
    // The other writer's rename lands between this writer's stat and its own.
    const spy = failingRename("ENOENT", () => {
      fs.copyFileSync(file, `${file}.1`);
      fs.unlinkSync(file);
    });
    try {
      appendCapped(file, "mine\n", 100);
    } finally {
      spy.mockRestore();
    }
    expect(fs.readFileSync(file, "utf-8")).toBe("mine\n");
  });

  for (const code of ["EBUSY", "EPERM", "EACCES"]) {
    it(`a rename refused with ${code} (a Windows reader holding the file, a read-only directory) never throws, and the line is appended`, () => {
      const file = path.join(tmpStateDir(), "t.jsonl");
      fs.writeFileSync(file, "x".repeat(97) + "\n");
      const spy = failingRename(code);
      try {
        expect(() => appendCapped(file, "mine\n", 100)).not.toThrow();
        expect(() => appendCapped(file, "again\n", 100)).not.toThrow();
      } finally {
        spy.mockRestore();
      }
      expect(fs.readFileSync(file, "utf-8").endsWith("mine\nagain\n")).toBe(true);
      expect(fs.existsSync(`${file}.1`)).toBe(false);
    });
  }

  it("once the rename works again, the next write rotates as usual", () => {
    const file = path.join(tmpStateDir(), "t.jsonl");
    fs.writeFileSync(file, "x".repeat(97) + "\n");
    const spy = failingRename("EBUSY");
    try {
      appendCapped(file, "held\n", 100);
    } finally {
      spy.mockRestore();
    }
    appendCapped(file, "after\n", 100);
    expect(fs.readFileSync(file, "utf-8")).toBe("after\n");
    expect(fs.readFileSync(`${file}.1`, "utf-8").endsWith("held\n")).toBe(true);
  });

  it("in a real read-only directory, a file at its cap still takes the line", () => {
    const dir = tmpStateDir();
    const file = path.join(dir, "t.jsonl");
    fs.writeFileSync(file, "x".repeat(97) + "\n");
    fs.chmodSync(dir, 0o555);
    try {
      expect(() => appendCapped(file, "mine\n", 100)).not.toThrow();
    } finally {
      fs.chmodSync(dir, 0o700);
    }
    expect(fs.readFileSync(file, "utf-8").endsWith("mine\n")).toBe(true);
  });

  it("writeTelemetry carries on through a failing rename", () => {
    const dir = tmpStateDir();
    const telemetry = path.join(dir, "t.jsonl");
    fs.writeFileSync(telemetry, "x".repeat(200) + "\n");
    const spy = failingRename("EBUSY");
    try {
      writeTelemetry({ enabled: true, path: telemetry, maxBytes: 100 }, row("ls"));
    } finally {
      spy.mockRestore();
    }
    const last = fs.readFileSync(telemetry, "utf-8").trim().split("\n").pop()!;
    expect(JSON.parse(last).command).toBe("ls");
  });
});

describe("telemetry and the log are capped", () => {
  it("writeTelemetry rotates at telemetry.maxBytes", () => {
    const file = path.join(tmpStateDir(), "t.jsonl");
    for (let i = 0; i < 40; i++) writeTelemetry({ enabled: true, path: file, maxBytes: 2000 }, row(`echo ${i}`));
    expect(fs.statSync(file).size).toBeLessThanOrEqual(2000);
    expect(fs.existsSync(`${file}.1`)).toBe(true);
    const last = fs.readFileSync(file, "utf-8").trim().split("\n").map((l) => JSON.parse(l)).pop();
    expect(last.command).toBe("echo 39");
  });

  it("writeTelemetry with no maxBytes uses the default cap", () => {
    const file = path.join(tmpStateDir(), "t.jsonl");
    fs.writeFileSync(file, "");
    fs.truncateSync(file, DEFAULT_TELEMETRY_MAX_BYTES);
    writeTelemetry({ enabled: true, path: file }, row("echo after"));
    expect(fs.statSync(`${file}.1`).size).toBe(DEFAULT_TELEMETRY_MAX_BYTES);
    expect(JSON.parse(fs.readFileSync(file, "utf-8")).command).toBe("echo after");
  });

  it("log rotates at LOG_MAX_BYTES", () => {
    const saved = process.env.AUTO_CLASSIFIER_LOG;
    const file = path.join(tmpStateDir(), "auto-classifier.log");
    process.env.AUTO_CLASSIFIER_LOG = file;
    try {
      fs.writeFileSync(file, "");
      fs.truncateSync(file, LOG_MAX_BYTES);
      log("after the cap");
      expect(fs.statSync(`${file}.1`).size).toBe(LOG_MAX_BYTES);
      expect(fs.readFileSync(file, "utf-8")).toContain("after the cap");
    } finally {
      process.env.AUTO_CLASSIFIER_LOG = saved;
    }
  });
});

describe("telemetry.maxBytes in config", () => {
  const load = (body: string) => {
    const file = path.join(tmpStateDir(), "config.jsonc");
    fs.writeFileSync(file, body);
    return loadConfig(file, { overlay: false });
  };

  it("defaults to DEFAULT_TELEMETRY_MAX_BYTES, and reads a number of bytes, 0 included", () => {
    expect(load("{}").telemetry.maxBytes).toBe(DEFAULT_TELEMETRY_MAX_BYTES);
    expect(load(`{ "telemetry": { "maxBytes": 1000000 } }`).telemetry.maxBytes).toBe(1000000);
    expect(load(`{ "telemetry": { "maxBytes": 0 } }`).telemetry.maxBytes).toBe(0);
  });

  it("ignores a value that is not a non-negative number", () => {
    expect(load(`{ "telemetry": { "maxBytes": "big" } }`).telemetry.maxBytes).toBe(DEFAULT_TELEMETRY_MAX_BYTES);
    expect(load(`{ "telemetry": { "maxBytes": -1 } }`).telemetry.maxBytes).toBe(DEFAULT_TELEMETRY_MAX_BYTES);
  });
});
