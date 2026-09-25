import { afterAll } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/**
 * Preloaded before every test file (bunfig.toml). A test must never write the
 * operator's real log or timeout records, and never reach a real tmux pane:
 * the watchers log to AUTO_CLASSIFIER_LOG, record timeouts under
 * AUTO_CLASSIFIER_STATE_DIR, and only start inside tmux. A test that wants a
 * log sets AUTO_CLASSIFIER_LOG itself.
 *
 * Every temporary directory a test makes (`os.tmpdir()`, here and in any git
 * or bun it spawns) lands under one directory for the run, removed after the
 * last test, so a test run leaves nothing behind in the system's temp dir.
 */
const run = fs.mkdtempSync(path.join(os.tmpdir(), "auto-classifier-tests-"));
process.env.TMPDIR = run;
// In a preload file, afterAll runs once, after the last test file.
afterAll(() => fs.rmSync(run, { recursive: true, force: true }));

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-classifier-test-home-"));
process.env.AUTO_CLASSIFIER_LOG = path.join(dir, "auto-classifier.log");
process.env.AUTO_CLASSIFIER_STATE_DIR = dir;
delete process.env.TMUX;
delete process.env.TMUX_PANE;
