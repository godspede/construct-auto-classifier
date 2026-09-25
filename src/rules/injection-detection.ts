/**
 * A deterministic tell that a command (or file content shown to the model)
 * is attempting to override this gate's own instructions -- a forged
 * system/assistant/developer turn, an explicit "ignore previous
 * instructions" directive, or a demand for the exact verdict JSON this gate
 * would emit.
 *
 * This is telemetry only: "allow, but tell you".
 * The harmless command inside an injection attempt still runs, so detection
 * here must never touch the decision path (see index.ts, which calls this
 * after the verdict is already decided). It is a
 * plain regex over the raw text rather than another question put to the
 * model, because a small/local model is not a reliable self-reporter of
 * having been manipulated, while a regex on the bytes it was actually asked
 * to judge fires the same way regardless of model or provider.
 *
 * These patterns catch the common shapes, not every phrasing -- a missed
 * attempt still gets the classifier's ordinary effect-based judgement; it
 * just isn't flagged.
 */
const INJECTION_PATTERNS: RegExp[] = [
  // A forged system/assistant/developer turn declaring the real rules void.
  /\b(?:system|assistant|developer)\s*:\s*[^\n]{0,80}\b(?:void|no longer appl(?:y|ies)|(?:are|is)\s+(?:cancelled|disabled|ignored))\b/i,
  // Direct override language, with or without a forged role marker.
  /\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above)\s+(?:rules?|instructions?|prompt|directives?)\b/i,
  // Dictating the exact verdict JSON this gate itself would emit.
  /reply\s+(?:with\s+)?\{?\s*["']?allow["']?\s*:\s*true/i,
];

/**
 * The pattern's own source when the text carries an injection tell, else
 * null. Callers pass the raw command and, separately, any file content --
 * this never parses or executes either, so it is safe to run before, after,
 * or instead of the LLM call.
 */
export function detectInjectionAttempt(text: string): string | null {
  for (const re of INJECTION_PATTERNS) {
    if (re.test(text)) return re.source;
  }
  return null;
}
