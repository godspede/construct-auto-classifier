/**
 * `policy.protectedBranches`: the branches whose force-push or deletion on a
 * remote is data destruction, and that a plain `git push` is never
 * fast-allowed to. One list, read by every place that names them -- the
 * default push fast-allow rule, script provenance's default-branch fallback,
 * the chat prompt and Jev's questions -- so they cannot disagree.
 */

export const DEFAULT_PROTECTED_BRANCHES: readonly string[] = ["main", "master"];

/** What a branch name may contain here: the characters the push fast-allow rule admits. */
const BRANCH_NAME = /^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/;

export function isBranchName(name: string): boolean {
  return BRANCH_NAME.test(name);
}

/** The configured list, or the default when there is none. */
export function protectedBranchList(list: readonly string[] | undefined): readonly string[] {
  return list ?? DEFAULT_PROTECTED_BRANCHES;
}

/** `main/master`, as the model-facing text names the branches. */
export function protectedBranchesText(list: readonly string[] | undefined): string {
  return protectedBranchList(list).join("/");
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\\/]/g, "\\$&");
}

/**
 * The default `rules.fastAllow` rule for a plain `git push <remote> <branch>`
 * to any branch but a protected one. Branch names are matched literally.
 */
export function pushFastAllowRule(list: readonly string[] | undefined): string {
  const names = protectedBranchList(list);
  const guard = names.length ? `(?!(?:${names.map(escapeRegex).join("|")})\\b)` : "";
  return `^\\s*git\\s+push(?:\\s+--set-upstream|\\s+-u)?\\s+[a-zA-Z0-9_.-]+\\s+${guard}[a-zA-Z0-9_.-]+(?:\\/[a-zA-Z0-9_.-]+)*\\s*$`;
}
