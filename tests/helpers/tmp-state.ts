import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/** A throwaway state directory so tests never touch the machine's real session store. */
export function tmpStateDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "auto-classifier-test-"));
}
