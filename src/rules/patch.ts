/**
 * Extract every target path a patch/apply_patch tool call touches.
 *
 * OpenCode's own tool (registered as `apply_patch`, some code paths also
 * check the alias `patch` -- both are handled by the plugin) accepts a
 * `patchText` string. Two header shapes are both live in OpenCode's own
 * source (`strings` on the installed binary shows both, and a comment on
 * `Vo.parsePatch` errors with "invalid git diff header" -- it is a generic
 * diff parser, not solely the OpenAI-specific envelope):
 *
 *   - OpenAI's `apply_patch` envelope: `*** Begin Patch` / `*** End Patch`,
 *     wrapping one `*** Add File: <path>` / `*** Update File: <path>` /
 *     `*** Delete File: <path>` line per file, optionally followed by
 *     `*** Move to: <path>` for a rename.
 *   - A plain unified diff: `diff --git a/<path> b/<path>`, or bare
 *     `--- a/<path>` / `+++ b/<path>` (or without the `a/`/`b/` prefix).
 *     `/dev/null` on either side means an add or a delete and names no path.
 *
 * This does not validate hunks or otherwise verify the patch applies -- it
 * only pulls out target paths, deliberately permissively (recognising
 * either shape, and never erroring on a line it does not recognise), because
 * the caller's job is to run every target through the same read/write
 * ladder a `read`/`write`/`edit` call gets, not to be the patch applier.
 *
 * Returns null when NOTHING recognizable is found -- the caller's rule for
 * that case is "never allow", not "guess there were no targets".
 */
export function parsePatchTargets(patchText: string): string[] | null {
  const targets = new Set<string>();
  const lines = patchText.split(/\r?\n/);

  for (const line of lines) {
    let m = /^\*\*\*\s+(?:Add|Update|Delete)\s+File:\s*(.+?)\s*$/.exec(line);
    if (m) {
      targets.add(m[1]);
      continue;
    }
    m = /^\*\*\*\s+Move to:\s*(.+?)\s*$/.exec(line);
    if (m) {
      targets.add(m[1]);
      continue;
    }
    m = /^diff --git a\/(.+?) b\/(.+?)\s*$/.exec(line);
    if (m) {
      targets.add(m[1]);
      targets.add(m[2]);
      continue;
    }
    m = /^---\s+(?:a\/)?(.+?)(?:\t.*)?\s*$/.exec(line);
    if (m && m[1] !== "/dev/null") {
      targets.add(m[1]);
      continue;
    }
    m = /^\+\+\+\s+(?:b\/)?(.+?)(?:\t.*)?\s*$/.exec(line);
    if (m && m[1] !== "/dev/null") {
      targets.add(m[1]);
      continue;
    }
  }

  return targets.size > 0 ? [...targets] : null;
}
