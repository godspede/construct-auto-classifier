/**
 * Where a file-tool target lands, and whether that is inside the session's
 * workspace. Every file-tool rule is checked on the path as written AND on
 * where the kernel would actually write it (`resolveRealPath`), so a symlink
 * anywhere on the way (`ln -s /etc ./etc` inside the workspace, a link under
 * `/tmp`, a dangling link, a link to a link) and a `../../etc/passwd`
 * traversal cannot make an outside path read as inside.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/** How many links one resolution follows before it stops, as the kernel's ELOOP limit does. */
const MAX_LINK_HOPS = 40;

function components(p: string): string[] {
  return p.split(path.sep === "\\" ? /[\\/]+/ : /\/+/).filter((c) => c !== "");
}

/**
 * Where a write to `target` physically lands, walked the way the kernel walks
 * it: one component at a time, following a symlink wherever one sits (the
 * last component, a directory on the way, a dangling link, which a write
 * through creates, or a link to a link), with `..` applied to the directory
 * reached so far rather than to the letters (`link/..` is the parent of the
 * link's target, not the directory holding the link). From the first
 * component that does not exist, the rest is joined on unresolved: that is
 * where a write would create it. A relative `target` is taken against this
 * process's working directory; callers that know a better one join it first.
 * A link loop stops the walk where it is (the kernel refuses such a path).
 *
 * Decision-time only: nothing stops the filesystem changing between this
 * answer and the write it judged.
 */
export function resolveRealPath(target: string): string {
  const start = path.isAbsolute(target) ? target : `${process.cwd()}${path.sep}${target}`;
  const root = path.parse(start).root;
  const pending = components(start.slice(root.length));
  let resolved = root;
  // The longest prefix of `resolved` known to exist, with every link in it followed.
  let realPrefix = root;
  let exists = true;
  let hops = 0;
  while (pending.length > 0) {
    const c = pending.shift()!;
    if (c === ".") continue;
    if (c === "..") {
      resolved = path.dirname(resolved);
      if (exists) realPrefix = resolved;
      else if (resolved === realPrefix) exists = true;
      continue;
    }
    const next = path.join(resolved, c);
    if (!exists) {
      resolved = next;
      continue;
    }
    let link: string | null = null;
    try {
      const stat = fs.lstatSync(next);
      if (stat.isSymbolicLink()) {
        if (++hops > MAX_LINK_HOPS) throw new Error("link loop");
        link = fs.readlinkSync(next);
      }
    } catch {
      // Missing, unreadable, or a loop: nothing further exists to follow.
      exists = false;
      realPrefix = resolved;
      resolved = next;
      continue;
    }
    if (link === null) {
      resolved = next;
      realPrefix = next;
      continue;
    }
    const linkRoot = path.parse(link).root;
    if (path.isAbsolute(link)) {
      resolved = linkRoot;
      realPrefix = linkRoot;
    }
    pending.unshift(...components(link.slice(linkRoot.length)));
  }
  return resolved;
}

/** True when `target` is `root` or falls under it (both already resolved). */
export function isWithinRoot(target: string, root: string): boolean {
  const rel = path.relative(root, target);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/** `~`, `$HOME` and `${HOME}` at the start of a path, as a shell would expand them. */
export function expandHome(p: string): string {
  const home = process.env.HOME || os.homedir();
  return p.replace(/^(?:~|\$HOME|\$\{HOME\})(?=[\/\\]|$)/, () => home);
}

/**
 * Every location a file tool's `target` can be taken to name, for a rule to
 * hold on each: the target placed by its letters (`path.resolve`, `..`
 * folded textually), and where the kernel would write it (`resolveRealPath`
 * of the unfolded join). A target starting with `~` or `$HOME` is placed both
 * as written (a harness may not expand it) and expanded. A relative target is
 * placed only against an absolute `cwd`, never against this process's own
 * working directory; with none, the result is empty.
 */
export function targetLocations(target: string, cwd?: string): string[] {
  const out = new Set<string>();
  const candidates = [target];
  const expanded = expandHome(target);
  if (expanded !== target) candidates.push(expanded);
  for (const c of candidates) {
    const joined = path.isAbsolute(c) ? c : cwd && path.isAbsolute(cwd) ? `${cwd}${path.sep}${c}` : null;
    if (joined === null) continue;
    out.add(path.resolve(joined));
    out.add(resolveRealPath(joined));
  }
  return [...out];
}

/**
 * The target as written plus every location it names (`targetLocations`):
 * a rule matched on path text (a secret, the gate's files, a startup
 * location) applies when it matches any of them.
 */
export function targetSpellings(target: string, cwd?: string): string[] {
  return [...new Set([target, ...targetLocations(target, cwd)])];
}

/** A root as written (resolved) and where it really is, for comparing both kinds of location. */
export function rootForms(root: string): string[] {
  return [...new Set([path.resolve(root), resolveRealPath(path.resolve(root))])];
}

/**
 * True when `target` is itself a symlink (dangling or not), placed as the
 * kernel would place it. A write through one lands wherever it points, and a
 * link can be re-pointed after the gate looked.
 */
export function isSymlinkTarget(target: string, cwd?: string): boolean {
  const joined = path.isAbsolute(target) ? target : cwd && path.isAbsolute(cwd) ? `${cwd}${path.sep}${target}` : null;
  if (joined === null) return false;
  for (const p of new Set([joined, path.resolve(joined)])) {
    try {
      if (fs.lstatSync(p).isSymbolicLink()) return true;
    } catch {
      // does not exist: nothing to follow
    }
  }
  return false;
}

/**
 * True when every location `targetPath` (absolute, or relative to `cwd`)
 * names lies inside `cwd`, compared by its letters and where it really lands
 * (`targetLocations`).
 */
export function isWithinWorkspace(targetPath: string, cwd: string): boolean {
  const roots = rootForms(cwd);
  const locations = targetLocations(targetPath, path.resolve(cwd));
  return locations.length > 0 && locations.every((loc) => roots.some((r) => isWithinRoot(loc, r)));
}
