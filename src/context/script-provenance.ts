import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { analyzeCommand, type Segment } from "../rules/command-shape.js";

/**
 * What can be established about a script the agent is about to run, from the
 * file system and git rather than from the model's imagination.
 *
 * `landed` is the load-bearing fact: the file's content is byte-identical to
 * the copy on the repo's remote default branch, which means it went through
 * whatever gate that branch has. A landed script needs no classifier; an
 * unlanded one gets its content shown to the model with a line saying why it
 * is unlanded (modified locally, untracked, or not in a repo at all).
 */
export interface ScriptProvenance {
  /** Absolute path the command resolves to. */
  path: string;
  exists: boolean;
  /** Inside a git work tree and known to the index. */
  tracked: boolean;
  /** Content identical to the remote default branch's copy. */
  landed: boolean;
  /** `<remote>/<branch>` the content was compared against, when one was found. */
  ref?: string;
  /** Path relative to the repo root, when in one. */
  repoPath?: string;
  /** Script content, capped, when it is not landed and the file is readable. */
  content?: string;
  /** `content` is a head-slice: the file is longer than what is shown. */
  truncated?: boolean;
  /** The file's true length in characters, present when `truncated` is true. */
  originalLength?: number;
  /** One line for the prompt: what is known about where this file came from. */
  summary: string;
}

export interface GitRunner {
  (args: string[], cwd: string): { status: number; stdout: string };
}

export const defaultGit: GitRunner = (args, cwd) => {
  const r = spawnSync("git", args, { cwd, encoding: "utf-8", timeout: 5000, stdio: ["ignore", "pipe", "ignore"] });
  return { status: r.status ?? 1, stdout: (r.stdout ?? "").trim() };
};

const SCRIPT_RUNNERS = new Set(["bash", "sh", "zsh", "dash", "ksh", "fish", "python", "python2", "python3", "node", "bun", "deno", "perl", "ruby", "php", "lua", "source", "."]);
const SCRIPT_RUNNER_FILE_FLAGS: Record<string, string> = { pwsh: "-File", powershell: "-File" };
const OUTPUT_SHAPERS = new Set(["head", "tail", "cat", "less", "more", "wc", "tee", "grep"]);

export interface ScriptInvocation {
  /** The script path as written. */
  script: string;
  /** A `cd DIR &&` prefix, if the line had one. */
  cd?: string;
}

/** `/opt/app/.venv/bin/python3.12` -> `python3`; a runner named by path is still a runner. */
function runnerName(verb: string): string {
  const base = verb.replace(/^.*[\/\\]/, "").replace(/\.exe$/i, "");
  const m = /^(python)(\d?)(?:\.\d+)*$/.exec(base);
  return m ? m[1] + m[2] : base;
}

function scriptFromSegment(seg: Segment): string | null {
  const verb = seg.verb;
  if (!verb) return null;
  const runner = runnerName(verb);
  const isPath = verb.startsWith("./") || verb.startsWith("../") || verb.startsWith("/") || verb.startsWith("~/");
  // An interpreter given by path (a virtualenv's bin/python, /usr/bin/node) is
  // the interpreter, not a script: its own bytes are not what the agent wrote.
  if (isPath && !SCRIPT_RUNNERS.has(runner)) return verb;
  if (SCRIPT_RUNNERS.has(runner)) {
    // first non-flag argument that looks like a file, unless inline code was given
    const args = seg.args;
    if (args.some((a) => a === "-c" || a === "-e" || a === "-m")) return null;
    const file = args.find((a) => !a.startsWith("-"));
    return file && /\.[A-Za-z0-9]+$|\//.test(file) ? file : null;
  }
  const fileFlag = SCRIPT_RUNNER_FILE_FLAGS[verb.toLowerCase()];
  if (fileFlag) {
    const i = seg.args.findIndex((a) => a.toLowerCase() === fileFlag.toLowerCase());
    return i !== -1 && seg.args[i + 1] ? seg.args[i + 1] : null;
  }
  return null;
}

/**
 * Recognise a line that runs exactly one script: `./x.sh`, `bash x.sh`,
 * `python3 tools/x.py args`, `pwsh -File x.ps1`, optionally behind `cd DIR &&`
 * and ahead of `| tail -N`. Anything more complicated is not a script run and
 * gets no provenance; the classifier sees the line as it is.
 */
export function findScriptInvocation(command: string): ScriptInvocation | null {
  const shape = analyzeCommand(command);
  if (shape.hasSubstitution) return null;
  const segs = shape.segments.filter((s) => s.words.length > 0);
  let cd: string | undefined;
  let i = 0;
  if (segs[i]?.verb === "cd" && segs[i].args.length === 1) {
    cd = segs[i].args[0];
    i++;
  }
  const main = segs[i];
  if (!main) return null;
  const script = scriptFromSegment(main);
  if (!script) return null;
  for (const rest of segs.slice(i + 1)) {
    if (!OUTPUT_SHAPERS.has(rest.verb)) return null;
  }
  return { script, cd };
}

function expandHome(p: string): string {
  return p === "~" ? os.homedir() : p.startsWith("~/") ? path.join(os.homedir(), p.slice(2)) : p;
}

/** The remote-tracking ref for the repo's default branch, if any remote has one. */
function defaultBranchRef(git: GitRunner, repoRoot: string): string | null {
  const remotes = git(["remote"], repoRoot);
  if (remotes.status !== 0) return null;
  for (const remote of remotes.stdout.split("\n").filter(Boolean)) {
    const head = git(["symbolic-ref", "-q", `refs/remotes/${remote}/HEAD`], repoRoot);
    if (head.status === 0 && head.stdout) return head.stdout.replace(/^refs\/remotes\//, "");
    for (const branch of ["main", "master", "development"]) {
      if (git(["rev-parse", "-q", "--verify", `refs/remotes/${remote}/${branch}`], repoRoot).status === 0) {
        return `${remote}/${branch}`;
      }
    }
  }
  return null;
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

export interface ProvenanceOptions {
  maxChars?: number;
  git?: GitRunner;
}

export function scriptProvenance(command: string, cwd: string, opts: ProvenanceOptions = {}): ScriptProvenance | null {
  const inv = findScriptInvocation(command);
  if (!inv) return null;
  const git = opts.git ?? defaultGit;
  const maxChars = opts.maxChars ?? 2000;

  const base = inv.cd ? path.resolve(cwd, expandHome(inv.cd)) : cwd;
  const abs = path.resolve(base, expandHome(inv.script));
  const exists = fs.existsSync(abs) && fs.statSync(abs).isFile();
  const dir = path.dirname(abs);

  const readCapped = (): { content: string; truncated: boolean; originalLength: number } | undefined => {
    if (!exists) return undefined;
    try {
      const full = fs.readFileSync(abs, "utf-8");
      return { content: full.slice(0, maxChars), truncated: full.length > maxChars, originalLength: full.length };
    } catch {
      return undefined;
    }
  };

  if (!exists) {
    return { path: abs, exists: false, tracked: false, landed: false, summary: `script ${abs} does not exist` };
  }
  // A compiled executable is not a script anyone can review by reading it;
  // showing the model its first 2,000 bytes would only ever read as a
  // truncated file. The line is classified as written instead.
  if (isBinary(abs)) return null;

  const root = git(["rev-parse", "--show-toplevel"], dir);
  if (root.status !== 0 || !root.stdout) {
    const read = readCapped();
    return { path: abs, exists, tracked: false, landed: false, content: read?.content, truncated: read?.truncated, originalLength: read?.originalLength, summary: `script ${abs} is not inside a git repository` };
  }
  const repoRoot = root.stdout;
  const repoPath = path.relative(repoRoot, abs).split(path.sep).join("/");
  const tracked = git(["ls-files", "--error-unmatch", "--", repoPath], repoRoot).status === 0;
  if (!tracked) {
    const read = readCapped();
    return { path: abs, exists, tracked: false, landed: false, repoPath, content: read?.content, truncated: read?.truncated, originalLength: read?.originalLength, summary: `script ${repoPath} is UNTRACKED in its repository (never committed, never reviewed)` };
  }

  const ref = defaultBranchRef(git, repoRoot);
  const localBlob = git(["hash-object", "--", abs], repoRoot);
  const remoteBlob = ref ? git(["rev-parse", "-q", "--verify", `${ref}:${repoPath}`], repoRoot) : null;
  const landed = !!(ref && localBlob.status === 0 && remoteBlob && remoteBlob.status === 0 && remoteBlob.stdout === localBlob.stdout);

  if (landed) {
    return { path: abs, exists, tracked, landed, ref: ref!, repoPath, summary: `script ${repoPath} is tracked and byte-identical to ${ref} (it went through that branch's own merge gate)` };
  }
  const why = !ref ? "no remote default branch to compare against" : remoteBlob?.status !== 0 ? `not present on ${ref}` : `MODIFIED locally relative to ${ref}`;
  const read = readCapped();
  return { path: abs, exists, tracked, landed: false, ref: ref ?? undefined, repoPath, content: read?.content, truncated: read?.truncated, originalLength: read?.originalLength, summary: `script ${repoPath} is tracked but ${why}` };
}
