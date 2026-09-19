/**
 * Deterministic, config-independent refusal of anything that would write,
 * move, delete, chmod, or otherwise mutate the classifier's own gate -- its
 * config/telemetry directory, its installed plugin file, or an
 * `AUTO_CLASSIFIER_*` environment override that redirects it to a config it
 * never chose.
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
 * `isProtectedPath` is exported standalone because a follow-up guard on
 * opencode's own edit/write tools -- which receive a target path directly,
 * with no shell command to parse -- needs the identical predicate.
 */
import type { CommandShape, Segment } from "./command-shape.js";
import { envAssignments, redirectTargets } from "./command-shape.js";

const PROTECTED_PATH_PATTERNS: RegExp[] = [
  // ~/.config/auto-classifier/** -- config.jsonc, telemetry.jsonl, auto-classifier.log
  /(?:^|[\/\\])\.config[\/\\]auto-classifier(?:[\/\\]|$)/i,
  // the installed plugin drop-in opencode loads on start
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
 * -x`/`typeset -x`, or via `env NAME=value realcmd`.
 */
function allEnvAssignments(seg: Segment): string[] {
  const verb = seg.verb.replace(/^.*[\/\\]/, "");

  if (verb === "") {
    // Every word parsed as a leading assignment and nothing left to be a
    // verb: the whole segment is bare `NAME=value` word(s).
    return seg.words.filter((w) => ASSIGNMENT.test(w));
  }

  const out = envAssignments(seg);
  if (verb === "export" || verb === "declare" || verb === "typeset") {
    out.push(...seg.args.filter((a) => ASSIGNMENT.test(a)));
  }
  if (verb === "env") {
    for (const a of seg.args) {
      if (!ASSIGNMENT.test(a)) break; // the command env then runs
      out.push(a);
    }
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

/**
 * Scan an already-analyzed command for any simple command that targets the
 * classifier's own gate. Returns a human-readable reason, or null when
 * nothing in the line touches it.
 */
export function selfProtectionDenial(shape: CommandShape): string | null {
  for (const seg of shape.segments) {
    const verb = seg.verb.replace(/^.*[\/\\]/, ""); // /usr/bin/tee -> tee

    for (const assignment of allEnvAssignments(seg)) {
      const name = assignment.slice(0, assignment.indexOf("="));
      if (isProtectedEnvOverride(name)) {
        return `${name}= would override the classifier's own config`;
      }
    }

    for (const target of redirectTargets(seg)) {
      if (isProtectedPath(target)) {
        return `redirects into the classifier's own ${target}`;
      }
    }

    if (MUTATING_VERBS.has(verb) && bareArgs(seg).some(isProtectedPath)) {
      return `${verb} targets the classifier's own gate`;
    }

    if (verb === "sed" && seg.args.some((a) => /^-i/.test(a)) && bareArgs(seg).some(isProtectedPath)) {
      return `sed -i edits the classifier's own gate`;
    }

    if (verb === "find" && seg.args.some((a) => FIND_ACTION.test(a)) && bareArgs(seg).some(isProtectedPath)) {
      return `find with an action targets the classifier's own gate`;
    }
  }
  return null;
}
