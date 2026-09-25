import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { analyzeCommand, SECRET_PATH, type Segment } from "../rules/command-shape.js";
import { protectedBranchList } from "../protected-branches.js";
import { withheldNote } from "./file-references.js";

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
  /**
   * The line is exactly the narrow shape `findScriptInvocation` documents: the
   * script run on its own, by its path or by a bare interpreter name, with
   * plain arguments and nothing else. Only a plain run of a landed script is
   * what that branch's review vouched for.
   */
  plain: boolean;
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
  /**
   * Present when the gate withheld the script's contents (one of its own files,
   * or a credential-looking path): the file's size in bytes. `content` is then
   * only a note saying so, and a model allow of the run floors to ask.
   */
  withheldBytes?: number;
  /** One line for the prompt: what is known about where this file came from. */
  summary: string;
}

export interface GitRunner {
  (args: string[], cwd: string): { status: number; stdout: string };
}

export const defaultGit: GitRunner = (args, cwd) => {
  // Git's own location variables override repository discovery from `cwd`. A
  // host process can carry them: OpenCode keeps a snapshot repository of its own
  // and manipulates GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE/GIT_OBJECT_DIRECTORY
  // around it, so an inherited GIT_DIR makes `git remote get-url origin` answer
  // about THAT repository -- which has no `origin`, so the gate reads a
  // sanctioned push's remote as unreadable and falsely denies it. Drop them so
  // git always resolves the repository the cwd names. `git -c` still works (it
  // rides in `args`, not the environment).
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of Object.keys(env)) if (/^GIT_/i.test(key)) delete env[key];
  const r = spawnSync("git", args, { cwd, env, encoding: "utf-8", timeout: 5000, stdio: ["ignore", "pipe", "ignore"], windowsHide: true });
  return { status: r.status ?? 1, stdout: (r.stdout ?? "").trim() };
};

const SCRIPT_RUNNERS = new Set(["bash", "sh", "zsh", "dash", "ksh", "fish", "python", "python2", "python3", "node", "bun", "deno", "perl", "ruby", "php", "lua", "source", "."]);
const SCRIPT_RUNNER_FILE_FLAGS: Record<string, string> = { pwsh: "-File", powershell: "-File" };
/**
 * Verbs a script's output may be piped into with the line still recognized as
 * a script run, so the model is shown the script's content. Recognition only:
 * a pipe of any kind makes the line not `plain`, so it is never allowed for
 * being landed. `tee` writes files, so it is not one.
 */
const OUTPUT_SHAPERS = new Set(["head", "tail", "cat", "less", "more", "wc", "grep"]);

export interface ScriptInvocation {
  /** The script path as written. */
  script: string;
  /** A `cd DIR &&` prefix, if the line had one. */
  cd?: string;
  /**
   * The whole line is one simple command in the narrowest shape: the
   * script's own path as the verb (`./x.sh`, `../x.sh`, `/abs/x.sh`, `~/x.sh`), or a bare
   * interpreter name from `TRUSTED_INTERPRETERS` (resolved from PATH, never a
   * path to one) followed straight by the script, then only arguments made of
   * `PLAIN_WORD` characters that name no credential-looking path. That rules
   * out every env assignment, privilege wrapper, redirect (stdin, here-string
   * and here-document included), pipe, `;`, `&&`, `||`, `&`, `cd` prefix,
   * `source`/`.`, interpreter flag, quote, expansion and glob, and any
   * construct `unmodelledConstructs` flags, such as a line past its length
   * cap. A line that is
   * not plain may still be a script run, so its content is shown to the
   * model, but it is never allowed for being landed.
   */
  plain: boolean;
}

/** Interpreters trusted by bare name only, straight before the script with no flag of their own. */
const TRUSTED_INTERPRETERS = new Set(["bash", "sh", "zsh", "dash", "ksh", "python", "python2", "python3", "node", "perl", "ruby"]);
/** A word with no shell metacharacter, quote, expansion or glob: it reaches the script exactly as written. */
const PLAIN_WORD = /^[A-Za-z0-9_\-.\/:=,+@%]+$/;

/**
 * The script a line runs, when the line is exactly the narrow shape `plain`
 * describes; null otherwise. Read off the raw text, not the parsed segment,
 * so nothing the parser strips (a `sudo`, an env prefix, a redirect) can
 * disappear before it is checked.
 */
function narrowScriptRun(command: string): string | null {
  const words = command.trim().split(/[ \t]+/);
  const pathWord = (w: string | undefined) => !!w && /^(?:\.{1,2}\/|\/|~\/)/.test(w) && PLAIN_WORD.test(w.replace(/^~\//, ""));
  let script: string;
  let args: string[];
  if (pathWord(words[0])) {
    script = words[0]!;
    args = words.slice(1);
  } else if (TRUSTED_INTERPRETERS.has(words[0]!) && words[1] !== undefined && !words[1].startsWith("-") && (pathWord(words[1]) || PLAIN_WORD.test(words[1]))) {
    script = words[1];
    args = words.slice(2);
  } else {
    return null;
  }
  const plainArg = (a: string) => PLAIN_WORD.test(a) && !SECRET_PATH.test(a);
  return args.every(plainArg) ? script : null;
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
 * gets no provenance; the classifier sees the line as it is. Recognition is
 * wider than trust: only a line that is `plain` (see `ScriptInvocation`) is
 * ever allowed for running a landed script.
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
  const plain = segs.length === 1 && !shape.hasHeredoc && shape.unmodelled.length === 0 && narrowScriptRun(command) === script;
  return { script, cd, plain };
}

function expandHome(p: string): string {
  return p === "~" ? os.homedir() : p.startsWith("~/") ? path.join(os.homedir(), p.slice(2)) : p;
}

/**
 * The remote-tracking ref for the repo's default branch, if any remote has
 * one: the remote's HEAD, or else the first protected branch it carries.
 */
function defaultBranchRef(git: GitRunner, repoRoot: string, protectedBranches: readonly string[]): string | null {
  const remotes = git(["remote"], repoRoot);
  if (remotes.status !== 0) return null;
  for (const remote of remotes.stdout.split("\n").filter(Boolean)) {
    const head = git(["symbolic-ref", "-q", `refs/remotes/${remote}/HEAD`], repoRoot);
    if (head.status === 0 && head.stdout) return head.stdout.replace(/^refs\/remotes\//, "");
    for (const branch of protectedBranches) {
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
  /** `policy.protectedBranches`: tried in order when a remote names no default branch. */
  protectedBranches?: readonly string[];
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

  const readCapped = (): { content: string; truncated: boolean; originalLength?: number; withheldBytes?: number } | undefined => {
    if (!exists) return undefined;
    // A script that is one of the gate's files or credential-looking is not
    // shown; with none of it seen, an allow floors as for a cut-short one.
    const note = withheldNote(abs, cwd);
    if (note) return { content: note, truncated: false, withheldBytes: fs.statSync(abs).size };
    try {
      const full = fs.readFileSync(abs, "utf-8");
      return { content: full.slice(0, maxChars), truncated: full.length > maxChars, originalLength: full.length };
    } catch {
      return undefined;
    }
  };

  const plain = inv.plain;
  if (!exists) {
    return { path: abs, exists: false, tracked: false, landed: false, plain, summary: `script ${abs} does not exist` };
  }
  // A compiled executable is not a script anyone can review by reading it;
  // showing the model its first 2,000 bytes would only ever read as a
  // truncated file. The line is classified as written instead.
  if (isBinary(abs)) return null;

  const root = git(["rev-parse", "--show-toplevel"], dir);
  if (root.status !== 0 || !root.stdout) {
    const read = readCapped();
    return { path: abs, exists, tracked: false, landed: false, plain, content: read?.content, truncated: read?.truncated, originalLength: read?.originalLength, withheldBytes: read?.withheldBytes, summary: `script ${abs} is not inside a git repository` };
  }
  const repoRoot = root.stdout;
  const repoPath = path.relative(repoRoot, abs).split(path.sep).join("/");
  const tracked = git(["ls-files", "--error-unmatch", "--", repoPath], repoRoot).status === 0;
  if (!tracked) {
    const read = readCapped();
    return { path: abs, exists, tracked: false, landed: false, plain, repoPath, content: read?.content, truncated: read?.truncated, originalLength: read?.originalLength, withheldBytes: read?.withheldBytes, summary: `script ${repoPath} is UNTRACKED in its repository (never committed, never reviewed)` };
  }

  const ref = defaultBranchRef(git, repoRoot, protectedBranchList(opts.protectedBranches));
  const localBlob = git(["hash-object", "--", abs], repoRoot);
  const remoteBlob = ref ? git(["rev-parse", "-q", "--verify", `${ref}:${repoPath}`], repoRoot) : null;
  const landed = !!(ref && localBlob.status === 0 && remoteBlob && remoteBlob.status === 0 && remoteBlob.stdout === localBlob.stdout);

  if (landed) {
    const summary = `script ${repoPath} is tracked and byte-identical to ${ref} (it went through that branch's own merge gate)`;
    if (plain) return { path: abs, exists, tracked, landed, plain, ref: ref!, repoPath, summary };
    // Landed, but run in a way its review never saw: the model judges the
    // line, so it is shown the content too.
    const read = readCapped();
    return { path: abs, exists, tracked, landed, plain, ref: ref!, repoPath, content: read?.content, truncated: read?.truncated, originalLength: read?.originalLength, withheldBytes: read?.withheldBytes, summary };
  }
  const why = !ref ? "no remote default branch to compare against" : remoteBlob?.status !== 0 ? `not present on ${ref}` : `MODIFIED locally relative to ${ref}`;
  const read = readCapped();
  return { path: abs, exists, tracked, landed: false, plain, ref: ref ?? undefined, repoPath, content: read?.content, truncated: read?.truncated, originalLength: read?.originalLength, withheldBytes: read?.withheldBytes, summary: `script ${repoPath} is tracked but ${why}` };
}
