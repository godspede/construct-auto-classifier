import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { analyzeCommand } from "../rules/command-shape.js";
import { isGateDataPath, isSecretTarget } from "../rules/self-protection.js";

export interface ReferencedFile {
  path: string;
  content: string;
  truncated?: boolean;
  originalLength?: number;
  /**
   * Always `false`: a file found by this scan is data the command references
   * (`--body-file`, `-f`, a known extension), never the program it runs. The
   * executed-script path is `scriptProvenance`, whose truncated content *does*
   * floor the verdict.
   */
  executed?: boolean;
}

export interface FindReferencedFilesOptions {
  maxChars?: number;
}

const FILE_FLAGS = new Set([
  "-f",
  "--file",
  "--body-file",
  "-i",
  "--input",
  "-c",
  "--config",
]);

const FILE_EXTENSIONS = new Set([
  ".diff",
  ".patch",
  ".sql",
  ".json",
  ".jsonc",
  ".toml",
  ".yaml",
  ".yml",
  ".md",
  ".txt",
  ".csv",
  ".sh",
  ".py",
  ".js",
  ".ts",
  ".ps1",
  ".xml",
  ".html",
]);

/**
 * The note shown in place of a file's contents when the gate will not hand
 * them to the model: the gate's own settings (`isGateDataPath`) or a
 * credential-looking path (`isSecretTarget`), named directly or reached
 * through a link. Null when the file may be shown. The model still learns
 * the command references the file; redaction alone is best-effort, so a
 * secret's contents are never sent to be redacted.
 */
export function withheldNote(rawPath: string, cwd: string): string | null {
  const dir = path.resolve(cwd);
  const why = isGateDataPath(rawPath, dir) ? "one of the safety classifier's own files" : isSecretTarget(rawPath, dir) ? "a credential-looking path" : null;
  return why ? `[withheld by the gate: ${rawPath} is ${why}, so its contents are not shown]` : null;
}

function expandHome(p: string): string {
  return p === "~" ? os.homedir() : p.startsWith("~/") ? path.join(os.homedir(), p.slice(2)) : p;
}

function isBinary(file: string): boolean {
  try {
    const fd = fs.openSync(file, "r");
    const buf = Buffer.alloc(8192);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    fs.closeSync(fd);
    return buf.subarray(0, n).includes(0);
  } catch {
    return false;
  }
}

/**
 * Identify files referenced in a command line (via flags like -f/--file/--body-file,
 * input redirection <, or arguments ending with common file extensions), read their
 * contents up to maxChars, and return them for classifier inspection.
 */
export function findReferencedFiles(
  command: string,
  cwd: string,
  opts: FindReferencedFilesOptions = {}
): ReferencedFile[] {
  const maxChars = opts.maxChars ?? 2000;
  const shape = analyzeCommand(command);
  const candidatePaths: string[] = [];

  for (const seg of shape.segments) {
    const words = seg.words;
    for (let i = 0; i < words.length; i++) {
      const w = words[i]!;

      // Check flag-based file references (-f <file>, --file <file>, --body-file <file>)
      if (FILE_FLAGS.has(w.toLowerCase()) && i + 1 < words.length) {
        const next = words[i + 1]!;
        if (!next.startsWith("-") && next !== "|" && next !== ">" && next !== "<") {
          candidatePaths.push(next);
        }
      }

      // Check flag with = (--file=path, --config=path)
      const eqIdx = w.indexOf("=");
      if (eqIdx !== -1) {
        const flag = w.slice(0, eqIdx).toLowerCase();
        const val = w.slice(eqIdx + 1);
        if (FILE_FLAGS.has(flag) && val) {
          candidatePaths.push(val);
        }
      }

      // Check extension-based file references
      if (!w.startsWith("-") && !w.includes("://") && !w.startsWith("$")) {
        const ext = path.extname(w).toLowerCase();
        if (FILE_EXTENSIONS.has(ext)) {
          candidatePaths.push(w);
        }
      }
    }
  }

  // Deduplicate and resolve
  const resolvedFiles: ReferencedFile[] = [];
  const seen = new Set<string>();

  for (const raw of candidatePaths) {
    try {
      const clean = raw.replace(/^["']|["']$/g, "");
      if (!clean) continue;
      const abs = path.resolve(cwd, expandHome(clean));
      if (seen.has(abs)) continue;
      seen.add(abs);

      if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) continue;

      // The gate's own files and credential-looking ones are named, never
      // read: the model is told the file is there and was withheld.
      const note = withheldNote(clean, cwd) ?? withheldNote(abs, cwd);
      if (note) {
        resolvedFiles.push({ path: clean, content: note, executed: false });
        continue;
      }

      if (isBinary(abs)) continue;

      const full = fs.readFileSync(abs, "utf-8");
      const truncated = full.length > maxChars;
      const content = truncated ? full.slice(0, maxChars) : full;

      resolvedFiles.push({
        path: clean,
        content,
        truncated,
        originalLength: full.length,
        executed: false,
      });
    } catch {
      // Ignore unreadable or inaccessible files
    }
  }

  return resolvedFiles;
}
