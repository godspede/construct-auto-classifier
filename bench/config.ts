/**
 * The configuration a certification run measures, loaded through the same
 * `loadConfig()` the gate itself runs, never a copy of its rules.
 *
 * With no shipped config it is the package defaults: `bench-config.jsonc`
 * alone. A deployment that ships its own config file (a replacement
 * `rules.fastAllow`, say) is running a different gate, so certifying the
 * defaults says nothing about it: pass that file and the run measures it
 * instead, the way the gate loads it -- the file over the defaults, with no
 * machine-local overlay and no fallback model.
 *
 * Either way the battery's `sanctionedRemotes` placeholders replace whatever
 * the shipped file names. The upload cases are written against those
 * placeholder hosts, so a deployment's real destinations would score them
 * against a boundary they were never labelled for.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { deepMerge, loadConfig, parseJsonc } from "../src/config.js";
import type { AppConfig } from "../src/types.js";

export const BENCH_CONFIG = path.join(import.meta.dir, "bench-config.jsonc");

export function benchConfig(shippedConfig?: string): AppConfig {
  if (!shippedConfig) return loadConfig(BENCH_CONFIG, { overlay: false });

  const shipped = parseJsonc<Record<string, unknown>>(fs.readFileSync(shippedConfig, "utf-8"));
  const bench = parseJsonc<Record<string, unknown>>(fs.readFileSync(BENCH_CONFIG, "utf-8"));
  const merged = deepMerge(shipped, bench);
  delete merged.sanctionedRemotesFile;

  // loadConfig reads a file, so the merged config goes through one.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-classifier-bench-config-"));
  try {
    const file = path.join(dir, "config.jsonc");
    fs.writeFileSync(file, JSON.stringify(merged));
    return loadConfig(file, { overlay: false });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
