import { describe, it, expect } from "bun:test";
import fs from "node:fs";
import path from "node:path";
import { tmpStateDir } from "./helpers/tmp-state.js";

/**
 * The `auto-classifier` CLI, run as a process. The command it is asked about
 * is fast-allowed, so no model is reached.
 */
describe("auto-classifier check records the directory it judged in", () => {
  it("the telemetry row's cwd is the working directory, not null", () => {
    const home = tmpStateDir();
    const work = tmpStateDir();
    const telemetry = path.join(home, "t.jsonl");
    const config = path.join(home, "config.jsonc");
    fs.writeFileSync(config, JSON.stringify({ telemetry: { enabled: true, path: telemetry } }));
    const cli = path.join(import.meta.dir, "..", "src", "cli.ts");
    const r = Bun.spawnSync([process.execPath, cli, "check", "pwd"], {
      cwd: work,
      env: { ...process.env, HOME: home, AUTO_CLASSIFIER_CONFIG: config, AUTO_CLASSIFIER_LOCAL_CONFIG: path.join(home, "none.jsonc") },
    });
    expect(r.exitCode).toBe(0);
    const rows = fs.readFileSync(telemetry, "utf-8").trim().split("\n").map((l) => JSON.parse(l));
    expect(rows).toHaveLength(1);
    expect(rows[0].source).toBe("fast-allow");
    expect(fs.realpathSync(rows[0].cwd)).toBe(fs.realpathSync(work));
  });
});
