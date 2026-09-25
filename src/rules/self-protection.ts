/**
 * Deterministic, config-independent refusal of anything that would write,
 * move, delete, chmod, or otherwise mutate the classifier's own gate -- its
 * config/telemetry directory, its installed plugin file, its session state,
 * the code it runs from (`installRoot()`), or an `AUTO_CLASSIFIER_*`
 * environment override that redirects it to a config it never chose.
 *
 * This never consults `RulesConfig`: an operator-editable `fastDeny` list is
 * exactly the surface an agent escalating past the gate could edit away
 * first, so the check that protects the gate cannot live there. It still
 * returns a plain deny reason for `evaluateFastRules` to hand back as an
 * ordinary `matched: "deny"` -- which flows through the same
 * `AutoClassifier.handleDenial` escalation path as any other fast-deny
 * (`denyMode`, `consecutiveThreshold`). Repeating the command still reaches
 * the operator's prompt; this is never a dead end with no recourse, only a
 * verdict the model is never asked to make (and could make differently on
 * every retry).
 *
 * `isProtectedPath` and `isGatePath` are exported standalone because the
 * file-tool guards (OpenCode's read/write/edit/patch in index.ts and
 * adapters/opencode.ts, agy's in rules/file-write.ts), which receive a target
 * path directly with no shell command to parse, use the identical predicates.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { CommandShape, Segment } from "./command-shape.js";
import { effectiveCommand, redirectTargets, SECRET_PATH, unwrapSegment } from "./command-shape.js";
import { expandHome, isWithinRoot, resolveRealPath, rootForms, targetLocations, targetSpellings } from "./workspace.js";
import { gateConfigDir, homeDir } from "../paths.js";

const PROTECTED_PATH_PATTERNS: RegExp[] = [
  // ~/.config/auto-classifier/** -- config.jsonc, telemetry.jsonl, auto-classifier.log
  /(?:^|[\/\\])\.config[\/\\]auto-classifier(?:[\/\\]|$)/i,
  // the installed plugin drop-in OpenCode loads on start
  /(?:^|[\/\\])\.config[\/\\]opencode[\/\\]plugins[\/\\]auto-classifier\.js$/i,
  // per-session denial counters and remembered verdicts: a forged "allow"
  // here would be honoured as a cache hit
  /(?:^|[\/\\])\.cache[\/\\]auto-classifier(?:[\/\\]|$)/i,
  /(?:^|[\/\\])auto-classifier[\/\\]sessions(?:[\/\\]|$)/i,
];

/**
 * True when `rawPath` names any file or directory that IS the classifier's
 * own gate -- its config, telemetry, log, or installed plugin. `~` is
 * resolved to a placeholder home the same way `command-shape.ts` resolves it
 * for `SECRET_PATH`: the check is path-shaped, not user-shaped, so a literal
 * substitution is enough.
 */
export function isProtectedPath(rawPath: string): boolean {
  const normalized = rawPath.replace(/^~(?=[\/\\]|$)/, "/home/x");
  return PROTECTED_PATH_PATTERNS.some((re) => re.test(normalized));
}

/** The package name the gate's own package.json carries. */
const PACKAGE_NAME = "construct-auto-classifier";

/**
 * Where the running gate's code lives: its package root (the directory whose
 * package.json names this package, holding dist/, bin/, src/ ...) when there is
 * one within three levels of this module, else the one file the code is in (a
 * single-file bundle copied somewhere, such as an OpenCode plugin drop-in), or
 * the executable itself for a `bun build --compile` binary, whose modules live
 * in a virtual file system with no path on disk.
 *
 * Every shape this runs in resolves `moduleUrl` to a real file: a source run
 * to src/rules/self-protection.ts, the dist bundles (and bin/auto-classifier.js,
 * which imports dist/cli.js) to the bundle.
 */
export function resolveInstallRoot(moduleUrl: string = import.meta.url, execPath: string = process.execPath): string | null {
  if (/^file:\/\/\/(?:\$bunfs\/|[A-Za-z]:\/~BUN\/)/.test(moduleUrl)) return execPath;
  let file: string;
  try {
    file = fileURLToPath(moduleUrl);
  } catch {
    return null;
  }
  let dir = path.dirname(file);
  for (let i = 0; i < 4; i++) {
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf-8"));
      if (pkg?.name === PACKAGE_NAME) return dir;
    } catch {
      // no package.json here, or not one of ours
    }
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return file;
}

const foldCase = (p: string) => (process.platform === "win32" ? p.toLowerCase() : p);

let cachedInstallRoot: string | null | undefined;

/** `resolveInstallRoot()` for the running gate, symlinks resolved, computed once. */
export function installRoot(): string | null {
  if (cachedInstallRoot === undefined) {
    const root = resolveInstallRoot();
    cachedInstallRoot = root ? resolveRealPath(root) : null;
  }
  return cachedInstallRoot;
}

/**
 * True when `rawPath` is the gate's own code: `root` (default: the running
 * gate's `installRoot()`) or anything under it. A relative path is resolved
 * against `cwd`, and is never matched when no `cwd` is known. Symlinks and
 * `..` are resolved on both sides; the comparison ignores case on Windows.
 */
export function isInstallPath(rawPath: string, cwd?: string, root: string | null = installRoot()): boolean {
  if (!root || !rawPath) return false;
  const expanded = expandHome(rawPath.trim());
  // A relative path is placed only against a known, absolute directory:
  // resolving it against this process's own working directory would place
  // it wherever the gate happens to run (often its own checkout).
  if (!path.isAbsolute(expanded) && !(cwd && path.isAbsolute(cwd))) return false;
  const base = foldCase(resolveRealPath(root));
  // Both where its letters place it and where the kernel would land it
  // (`link/..` is the parent of the link's target).
  return targetLocations(expanded, cwd).some((loc) => isWithinRoot(foldCase(resolveRealPath(loc)), base));
}

/**
 * Files the loaded config was read from, or will be: the file
 * `AUTO_CLASSIFIER_CONFIG` names, the overlay `AUTO_CLASSIFIER_LOCAL_CONFIG`
 * names, and the `sanctionedRemotesFile` the config names. Each can live
 * outside `~/.config/auto-classifier`, and each decides what the gate allows,
 * so each is a gate file. `loadConfig` registers them, whether or not they
 * exist yet: an agent that created a missing one would be writing the gate's
 * config. Stored resolved (symlinks and `..` followed).
 */
const configuredGateFiles = new Set<string>();

/** Record `absPath` as one of the gate's own files; see `configuredGateFiles`. */
export function protectGateFile(absPath: string): void {
  if (!absPath || !path.isAbsolute(absPath)) return;
  configuredGateFiles.add(foldCase(resolveRealPath(absPath)));
}

/** True when `rawPath` (absolute, `~`, or relative to an absolute `cwd`) is a registered gate file. */
export function isConfiguredGateFile(rawPath: string, cwd?: string): boolean {
  if (configuredGateFiles.size === 0 || !rawPath) return false;
  const expanded = expandHome(rawPath.trim());
  if (!path.isAbsolute(expanded) && !(cwd && path.isAbsolute(cwd))) return false;
  return targetLocations(expanded, cwd).some((loc) => configuredGateFiles.has(foldCase(resolveRealPath(loc))));
}

/**
 * The files a hard link could share an inode with: every registered gate file,
 * each file directly in the gate's config directory, and its OpenCode plugin
 * drop-in. Stat'ed only when a target has a second link, which ordinary files
 * do not, so the common case costs one `stat`.
 */
function gateInodeFiles(): string[] {
  const files = [...configuredGateFiles, path.join(homeDir(), ".config", "opencode", "plugins", "auto-classifier.js")];
  try {
    for (const e of fs.readdirSync(gateConfigDir(), { withFileTypes: true })) {
      if (e.isFile()) files.push(path.join(gateConfigDir(), e.name));
    }
  } catch {
    // no config directory yet
  }
  return files;
}

/**
 * True when `rawPath` (absolute, `~`, or relative to an absolute `cwd`) is an
 * existing file with more than one link that shares its device and inode with
 * one of the gate's files (`gateInodeFiles`): a hard link is the file itself
 * under another name, so no path comparison can see it.
 */
export function isHardLinkToGateFile(rawPath: string, cwd?: string): boolean {
  if (!rawPath) return false;
  const expanded = expandHome(rawPath.trim());
  if (!path.isAbsolute(expanded) && !(cwd && path.isAbsolute(cwd))) return false;
  for (const loc of targetLocations(expanded, cwd)) {
    let st: fs.Stats;
    try {
      st = fs.statSync(loc);
    } catch {
      continue;
    }
    if (!st.isFile() || st.nlink < 2) continue;
    for (const file of gateInodeFiles()) {
      try {
        const g = fs.statSync(file);
        if (g.dev === st.dev && g.ino === st.ino) return true;
      } catch {
        // not there: nothing to share an inode with
      }
    }
  }
  return false;
}

/**
 * True when `rawPath` is any part of the gate: `isProtectedPath` (its config
 * directory, log, plugin drop-in, session state), `isInstallPath` (its code),
 * `isConfiguredGateFile` (a config, overlay or sanctioned-remotes file kept
 * elsewhere), or a hard link to one of its files (`isHardLinkToGateFile`).
 * Checked on the path as written and on every location it names
 * (`targetSpellings`), so a symlink to any of these is the gate too.
 */
export function isGatePath(rawPath: string, cwd?: string): boolean {
  return (
    isInstallPath(rawPath, cwd) ||
    isConfiguredGateFile(rawPath, cwd) ||
    targetSpellings(rawPath, cwd).some(isProtectedPath) ||
    isHardLinkToGateFile(rawPath, cwd)
  );
}

/**
 * True when `rawPath` holds the gate's own settings or state -- its config
 * directory, plugin drop-in, session state, a configured config file, or a
 * hard link to one -- as opposed to its code, which is harmless to read. What
 * a read refuses, and what is never shown to the model.
 */
export function isGateDataPath(rawPath: string, cwd?: string): boolean {
  return targetSpellings(rawPath, cwd).some(isProtectedPath) || isConfiguredGateFile(rawPath, cwd) || isHardLinkToGateFile(rawPath, cwd);
}

/** `isSecretPath` on the path as written and on every location it names, so a symlink to a secret is a secret. */
export function isSecretTarget(rawPath: string, cwd?: string): boolean {
  return targetSpellings(rawPath, cwd).some(isSecretPath);
}

/**
 * True when `rawPath` is a credential-looking path per `SECRET_PATH`
 * (`command-shape.ts`) -- the same regex that stops a fast-allowed `cat`
 * from vouching for reading one. A file-tool read of one of these gets no
 * model review at all: it is denied outright, the same way `isProtectedPath`
 * denies a write to the classifier's own gate without asking the model
 * whether this particular write is the dangerous kind.
 */
export function isSecretPath(rawPath: string): boolean {
  const normalized = rawPath.replace(/^~(?=[\/\\]|$)/, "/home/x");
  return SECRET_PATH.test(normalized);
}

/**
 * Directories a config-tool auth store lives in, whose OWN name does not
 * match `SECRET_PATH` (that regex is written against a specific filename
 * inside each, e.g. `.config/opencode/auth.json`) but whose *recursive
 * content* a directory-scoped search tool (`grep`/`glob`/`list`) would
 * surface regardless of which file inside actually holds the secret. A
 * single-file `read` of an unrelated file in one of these is unaffected --
 * `isSecretPath` alone still gates that, precisely, by filename; this is
 * additional and only for a tool whose `path` argument scopes a recursive
 * walk rather than naming one file to open.
 */
const SECRET_SEARCH_SCOPE_PATTERNS: RegExp[] = [
  /(?:^|[\/\\])\.config[\/\\]opencode(?:[\/\\]|$)/i,
  /(?:^|[\/\\])\.config[\/\\]gh(?:[\/\\]|$)/i,
  // A forge CLI's credential store, such as tea's or glab's, or that of any CLI named `<name>-forge`
  /(?:^|[\/\\])\.config[\/\\](?:tea|glab-cli|[\w.-]+-forge)(?:[\/\\]|$)/i,
];

/**
 * True when `rawPath` is a location a directory-scoped search
 * (`grep`/`glob`/`list`'s `path` argument) must not be free to scan: either
 * `isSecretPath` itself (which already covers a directory boundary for
 * `.ssh`/`.gnupg`/`.aws`/... -- reading anything under those trees is a
 * credential exposure regardless of filename), or one of the narrower
 * auth-store directories above.
 */
export function isSecretSearchScope(rawPath: string): boolean {
  const normalized = rawPath.replace(/^~(?=[\/\\]|$)/, "/home/x");
  return isSecretPath(normalized) || SECRET_SEARCH_SCOPE_PATTERNS.some((re) => re.test(normalized));
}

/**
 * Places a recursive search must not sweep up on the way to something else:
 * the gate's config directory and configured files, the home-directory
 * credential stores `SECRET_PATH` names, `~/.config` (every CLI's login lives
 * under it), and the system's `/etc` and `/proc`. OpenCode's grep searches
 * hidden files too, so a search scoped at `~` reads `~/.ssh`.
 */
function searchSensitiveLocations(): Array<[string, string]> {
  const home = homeDir();
  const inHome = [".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".password-store", ".netrc", ".pgpass", ".npmrc", ".pypirc", ".git-credentials", ".claude.json", ".claude", ".config"];
  return [
    [gateConfigDir(), "the safety classifier's own config directory"],
    ...[...configuredGateFiles].map((f): [string, string] => [f, "a config file of the safety classifier"]),
    ...inHome.map((p): [string, string] => [path.join(home, p), `~/${p}`]),
    ["/etc", "/etc"],
    ["/proc", "/proc"],
  ];
}

/**
 * What credential or gate location a recursive search scoped at `scope`
 * (absolute, `~`, or relative to an absolute `cwd`) would sweep up, or null
 * when it contains none. Compared as written and resolved on both sides.
 */
export function searchScopeCovers(scope: string, cwd?: string): string | null {
  const locations = targetLocations(scope, cwd);
  for (const [place, what] of searchSensitiveLocations()) {
    const forms = path.isAbsolute(place) ? rootForms(place) : [];
    if (locations.some((loc) => forms.some((f) => isWithinRoot(f, loc)))) return what;
  }
  return null;
}

/**
 * An env assignment that would point the classifier at a config, model,
 * timeout, or deny mode it did not choose. `AUTO_CLASSIFIER_CONFIG` is the
 * sharpest of these (it retargets the whole file) and `AUTO_CLASSIFIER_DENY_MODE`
 * the quietest (it does not touch a single file, only how loudly a future
 * denial escalates) -- every `AUTO_CLASSIFIER_*` variable configures the gate
 * itself, so all of them are protected.
 */
export function isProtectedEnvOverride(name: string): boolean {
  return /^(?:AUTO_CLASSIFIER_|TYPESAFE_)/i.test(name);
}

const ASSIGNMENT = /^([A-Za-z_][A-Za-z0-9_]*)=/;

/**
 * Every `NAME=value` token in a segment that could set an env var --
 * broader than `command-shape.ts`'s `envAssignments`, which only sees the
 * `NAME=value cmd` prefix form. A protected variable can also be set with no
 * command following it at all (`AUTO_CLASSIFIER_DENY_MODE=both` alone, a
 * shell variable a later `. `/`source` picks up), via `export`/`declare
 * -x`/`typeset -x`, or through a wrapper (`env -i NAME=value realcmd`,
 * `timeout 5 env NAME=value realcmd`, `env -S 'NAME=value realcmd'`), which
 * `effectiveCommand` collects.
 */
function allEnvAssignments(seg: Segment): string[] {
  const eff = effectiveCommand(seg);
  const out = [...eff.env];
  if (eff.verb === "export" || eff.verb === "declare" || eff.verb === "typeset") {
    out.push(...eff.args.filter((a) => ASSIGNMENT.test(a)));
  }
  return out;
}

/** Verbs whose bare (non-flag) arguments can name a file or directory to
 * overwrite, move, delete, or chmod. `sed`/`find` are handled separately:
 * their mutating intent lives in a flag (`-i`, `-delete`, `-exec`), not
 * automatically in every bare argument. */
const MUTATING_VERBS = new Set(["rm", "mv", "cp", "install", "tee", "truncate", "chmod", "chown", "chgrp", "shred", "ln", "rsync", "dd"]);

const FIND_ACTION = /^-(?:delete|exec|execdir|ok|okdir|fprint0?|fprintf|fls)$/;

function bareArgs(seg: Segment): string[] {
  return seg.args.filter((a) => !a.startsWith("-"));
}

/** A redirect the parser left among the words (`2>&1`, `>out`): never a path argument. */
const REDIRECT_WORD = /^\d*[<>]/;

/**
 * The arguments of a mutating verb that name a file it changes or reads to
 * change another: its bare arguments, minus a leading mode or owner
 * (`chmod 755`, `chown user:group`) and redirect words, and for `dd` only the
 * `of=` target.
 */
function pathArgs(verb: string, seg: Segment): string[] {
  if (verb === "dd") {
    return seg.args.filter((a) => a.startsWith("of=")).map((a) => a.slice(3));
  }
  let args = bareArgs(seg).filter((a) => !REDIRECT_WORD.test(a));
  if ((verb === "chmod" || verb === "chown" || verb === "chgrp") && !seg.args.some((a) => a.startsWith("--reference"))) {
    args = args.slice(1);
  }
  return args;
}

/** git subcommands that rewrite files in the working tree they run in. */
const GIT_WORKTREE_WRITES = new Set(["checkout", "switch", "reset", "restore", "pull", "merge", "rebase", "cherry-pick", "revert", "am", "apply", "stash", "clean", "rm", "mv"]);

/**
 * For a `git` segment, the working tree it runs in (its `-C` directories
 * applied to `cwd`) and its subcommand. `--git-dir`/`--work-tree` point it
 * somewhere else entirely, so their values are returned as places too.
 */
function gitInvocation(seg: Segment, cwd: string | undefined): { dirs: string[]; sub: string } {
  let dir = cwd;
  const dirs: string[] = [];
  const args = seg.args;
  let i = 0;
  for (; i < args.length; i++) {
    const a = args[i]!;
    if (a === "-C" && args[i + 1] !== undefined) {
      const next = expandHome(args[++i]!);
      dir = path.isAbsolute(next) ? next : dir ? path.resolve(dir, next) : undefined;
    } else if (a === "-c" && args[i + 1] !== undefined) {
      i++;
    } else if (/^--(?:git-dir|work-tree)=/.test(a)) {
      dirs.push(a.slice(a.indexOf("=") + 1));
    } else if (!a.startsWith("-")) {
      break;
    }
  }
  if (dir) dirs.push(dir);
  return { dirs, sub: args[i] ?? "" };
}

/**
 * Scan an already-analysed command for any simple command that targets the
 * classifier's own gate. Returns a human-readable reason, or null when
 * nothing in the line touches it.
 *
 * `cwd` is the directory the command runs in; a `cd DIR` on the line moves
 * it for the segments after. Without it, only an absolute (or `~`) path can
 * be placed inside the gate's own code.
 */
export function selfProtectionDenial(shape: CommandShape, cwd?: string): string | null {
  const isGate = (p: string) => isGatePath(p, cwd);
  for (const raw of shape.segments) {
    // The command that actually runs, through any wrapper (`timeout 5 rm`,
    // `env tee`, `xargs sed -i`) and however its verb is written
    // (`/usr/bin/tee`, `\rm`).
    const seg = unwrapSegment(raw);
    const verb = seg.verb;

    if (verb === "cd") {
      const dest = seg.args.find((a) => !a.startsWith("-"));
      if (dest !== undefined) {
        const next = expandHome(dest);
        cwd = path.isAbsolute(next) ? next : cwd ? path.resolve(cwd, next) : undefined;
      }
      continue;
    }

    if (verb === "git") {
      const { dirs, sub } = gitInvocation(seg, cwd);
      if (GIT_WORKTREE_WRITES.has(sub) && dirs.some((d) => isInstallPath(d, cwd))) {
        return `git ${sub} rewrites the classifier's own code`;
      }
    }

    for (const assignment of allEnvAssignments(raw)) {
      const name = assignment.slice(0, assignment.indexOf("="));
      if (isProtectedEnvOverride(name)) {
        return `${name}= would override the classifier's own config`;
      }
    }

    for (const target of redirectTargets(seg)) {
      if (isGate(target)) {
        return `redirects into the classifier's own ${target}`;
      }
    }

    if (MUTATING_VERBS.has(verb) && (bareArgs(seg).some(isProtectedPath) || pathArgs(verb, seg).some(isGate))) {
      return `${verb} targets the classifier's own gate`;
    }

    if (verb === "sed" && seg.args.some((a) => /^-i/.test(a)) && bareArgs(seg).filter((a) => !REDIRECT_WORD.test(a)).some(isGate)) {
      return `sed -i edits the classifier's own gate`;
    }

    if (verb === "find" && seg.args.some((a) => FIND_ACTION.test(a)) && bareArgs(seg).filter((a) => !REDIRECT_WORD.test(a)).some(isGate)) {
      return `find with an action targets the classifier's own gate`;
    }
  }
  return null;
}
