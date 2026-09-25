import fs from "node:fs";
import path from "node:path";
import type { RulesConfig } from "../types.js";
import { analyzeCommand, isRedirectTell, redirectTell, redirectWrites, unwrapSegment, type Redirect } from "./command-shape.js";
import { selfProtectionDenial } from "./self-protection.js";
import { isSensitiveWriteTarget } from "./sensitive-write.js";
import { resolveRealPath } from "./workspace.js";

export interface FastRuleMatch {
  matched: "allow" | "deny";
  pattern: string;
}

export const DEFAULT_SCRATCH_WRITE_ROOTS = ["/tmp/"];

function compile(patterns: string[] | undefined, kind: string): RegExp[] {
  const out: RegExp[] = [];
  for (const p of patterns ?? []) {
    try {
      out.push(new RegExp(p, "i"));
    } catch (err) {
      console.error(`[auto-classifier] Warning: invalid ${kind} regex: ${p}`, err);
    }
  }
  return out;
}

/**
 * A redirect target is scratch only if it lies inside a scratch root once
 * resolved: `/tmp/../etc/profile` starts with `/tmp/` and is not in it. A
 * relative target, or one containing `..` at all, is never scratch.
 */
export function isUnderScratchRoot(target: string, roots: string[]): boolean {
  if (!path.posix.isAbsolute(target) || target.split("/").includes("..")) return false;
  const resolved = path.posix.normalize(target);
  return roots.some((root) => {
    const r = path.posix.normalize(root.endsWith("/") ? root : root + "/");
    return resolved.startsWith(r);
  });
}

/**
 * A writing redirect a fast allow may still vouch for: a literal path (no
 * expansion the shell could turn into somewhere else) inside a scratch root,
 * still inside one once symlinks are followed, and not a sensitive startup
 * location (`isSensitiveWriteTarget`). Anything the scanner could not pin
 * down is never scratch.
 */
export function isScratchRedirect(r: Redirect, roots: string[]): boolean {
  if (r.kind !== "write" || !r.literal || !isUnderScratchRoot(r.target, roots)) return false;
  if (isSensitiveWriteTarget(r.target)) return false;
  // `/tmp/link -> ~/.bashrc` is under /tmp by its letters only. A link as the
  // last component is never scratch, dangling or not (a write through a
  // dangling one creates its target). Directories on the way are resolved,
  // and a root that is itself a symlink (macOS's /tmp) is compared in its
  // resolved form too.
  try {
    if (fs.lstatSync(r.target).isSymbolicLink()) return false;
  } catch {
    // does not exist yet: nothing to follow
  }
  const real = resolveRealPath(r.target);
  return isUnderScratchRoot(real, roots) || isUnderScratchRoot(real, roots.map((root) => resolveRealPath(root) + "/"));
}

/**
 * Decide a command without the LLM, or return null to defer to it.
 *
 * self-protection (see self-protection.ts) is checked first and is never
 * config-driven: it denies anything that writes, moves, deletes, chmods, or
 * env-overrides the classifier's own gate (`cwd` places a relative path), regardless of what rules.fastAllow
 * or rules.fastDeny say.
 *
 * fastDeny is matched against the whole line: a catastrophic pattern anywhere
 * is a denial. fastAllow is stricter than a regex match: the line is split into
 * simple commands, every one of them must match an allow rule after its
 * env/privilege prefix is stripped, and the line as a whole must carry none of
 * the structural tells that make a read-only verb write, execute, or escape
 * (file redirects outside a scratch root, `sed -i`, `find -delete`, `tee`,
 * `$( )`, an interpreter given inline code, a PATH= prefix, ...). A rule only
 * ever vouches for the verb it names; the structure check is what lets an
 * aggressive allow list stay safe to keep.
 */
export function evaluateFastRules(command: string, rules: RulesConfig, cwd?: string): FastRuleMatch | null {
  const trimmed = command.trim();
  if (!trimmed) {
    return { matched: "allow", pattern: "empty-command" };
  }

  const shape = analyzeCommand(trimmed);

  // Config-independent: checked before rules.fastDeny so an edit to
  // fastAllow/fastDeny (or its absence) can never let a command through that
  // mutates the classifier's own gate. See self-protection.ts for why this
  // cannot live in RulesConfig.
  const selfProtect = selfProtectionDenial(shape, cwd);
  if (selfProtect) {
    return { matched: "deny", pattern: `self-protection: ${selfProtect}` };
  }

  // A deny pattern is written against a line start, so test it against the
  // whole line and against every simple command in it: `ls; mkfs.ext4 /dev/sda`
  // is the mkfs, not the ls. Each simple command is also tested as it runs
  // once its wrappers are off (`timeout 5 mkfs.ext4`, `env dd …`, `\mkfs.ext4`,
  // `/sbin/mkfs.ext4`). More candidates can only find more denials.
  const candidates = [trimmed, ...shape.segments.flatMap((s) => [s.stripped, unwrapSegment(s).stripped])];
  for (const regex of compile(rules.fastDeny, "fastDeny")) {
    if (candidates.some((c) => regex.test(c))) {
      return { matched: "deny", pattern: regex.source };
    }
  }

  const allow = compile(rules.fastAllow, "fastAllow");
  if (allow.length === 0) return null;
  if (shape.hasSubstitution || shape.segments.length === 0) return null;
  // Syntax the analyser does not fully model (a comment, grouping, a compound
  // command, cross-shell quoting, a control or lookalike character, ...) is
  // never vouched for: these are tells too, and this says so outright.
  if (shape.unmodelled.length > 0) return null;

  const scratchRoots = rules.scratchWriteRoots ?? DEFAULT_SCRATCH_WRITE_ROOTS;
  // Redirect tells are re-derived from the scan itself rather than from their
  // text, so a tell's wording can never make a target look like scratch.
  const blocking = [
    ...shape.tells.filter((tell) => !isRedirectTell(tell)),
    ...shape.redirects.filter((r) => redirectWrites(r) && !isScratchRedirect(r, scratchRoots)).map(redirectTell),
  ];
  if (blocking.length > 0) return null;

  const matched: string[] = [];
  for (const seg of shape.segments) {
    const hit = allow.find((regex) => regex.test(seg.stripped));
    if (!hit) return null;
    matched.push(hit.source);
  }
  return { matched: "allow", pattern: matched.length === 1 ? matched[0] : matched.join(" ; ") };
}
