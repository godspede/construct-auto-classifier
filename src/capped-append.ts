import fs from "node:fs";
import path from "node:path";

/**
 * Append `text` to `file`, keeping the file at or under `maxBytes`: a write
 * that would take it past the cap first moves it to `<file>.1`, replacing any
 * older one, so at most two files' worth is kept. A cap of 0 never rotates.
 * Callers pass whole lines, so a rotation never splits one. A rotation that
 * fails never stops the write. Throws what creating the directory or the
 * append throws; each caller decides whether that may break anything.
 */
export function appendCapped(file: string, text: string, maxBytes: number): void {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  if (maxBytes > 0) {
    let size = 0;
    try {
      size = fs.statSync(file).size;
    } catch {
      // no file yet
    }
    if (size > 0 && size + Buffer.byteLength(text) > maxBytes) {
      try {
        fs.renameSync(file, `${file}.1`);
      } catch {
        // Another writer rotated it first (ENOENT), or the rename is refused
        // (a read-only directory; on Windows, a reader holding either file
        // open). The line is appended all the same, and a later write
        // rotates once the rename works again.
      }
    }
  }
  fs.appendFileSync(file, text, { mode: 0o600 });
}
