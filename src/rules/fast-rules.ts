import path from "node:path";
import type { RulesConfig } from "../types.js";
import { analyzeCommand } from "./command-shape.js";
import { selfProtectionDenial } from "./self-protection.js";

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
      console.error(`[auto-classifier] Invalid ${kind} regex: ${p}`, err);
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
 * Decide a command without the LLM, or return null to defer to it.
 *
 * self-protection (see self-protection.ts) is checked first and is never
 * config-driven: it denies anything that writes, moves, deletes, chmods, or
 * env-overrides the classifier's own gate, regardless of what rules.fastAllow
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
export function evaluateFastRules(command: string, rules: RulesConfig): FastRuleMatch | null {
  const trimmed = command.trim();
  if (!trimmed) {
    return { matched: "allow", pattern: "empty-command" };
  }

  const shape = analyzeCommand(trimmed);

  // Config-independent: checked before rules.fastDeny so an edit to
  // fastAllow/fastDeny (or its absence) can never let a command through that
  // mutates the classifier's own gate. See self-protection.ts for why this
  // cannot live in RulesConfig.
  const selfProtect = selfProtectionDenial(shape);
  if (selfProtect) {
    return { matched: "deny", pattern: `self-protection: ${selfProtect}` };
  }

  // A deny pattern is written against a line start, so test it against the
  // whole line and against every simple command in it: `ls; mkfs.ext4 /dev/sda`
  // is the mkfs, not the ls.
  const candidates = [trimmed, ...shape.segments.map((s) => s.stripped)];
  for (const regex of compile(rules.fastDeny, "fastDeny")) {
    if (candidates.some((c) => regex.test(c))) {
      return { matched: "deny", pattern: regex.source };
    }
  }

  const allow = compile(rules.fastAllow, "fastAllow");
  if (allow.length === 0) return null;
  if (shape.hasSubstitution || shape.segments.length === 0) return null;

  const scratchRoots = rules.scratchWriteRoots ?? DEFAULT_SCRATCH_WRITE_ROOTS;
  const blocking = shape.tells.filter((tell) => {
    const m = /^redirect to (.+)$/.exec(tell);
    return !(m && isUnderScratchRoot(m[1], scratchRoots));
  });
  if (blocking.length > 0) return null;

  const matched: string[] = [];
  for (const seg of shape.segments) {
    const hit = allow.find((regex) => regex.test(seg.stripped));
    if (!hit) return null;
    matched.push(hit.source);
  }
  return { matched: "allow", pattern: matched.length === 1 ? matched[0] : matched.join(" ; ") };
}
