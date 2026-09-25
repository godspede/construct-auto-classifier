import * as path from "node:path";
import { isConfiguredGateFile, isHardLinkToGateFile, isInstallPath, isProtectedPath, isSecretPath } from "./self-protection.js";
import { isSensitiveWriteTarget } from "./sensitive-write.js";
import { resolveRealPath } from "./workspace.js";

/**
 * Judging an agent's file-writing tool call (agy's write_to_file /
 * replace_file_content, OpenCode's edit / write / patch), where the harness
 * hands over a target path and there is no shell command to classify.
 *
 * Deterministic and model-free, because a file write's risk is almost all in
 * where it lands:
 *  - deny: the gate's own files (config, log, plugin, session state, and the
 *    code it runs from, or a hard link to one of its files), the same set the
 *    shell rules protect, so an edit tool cannot do what a redirect may not;
 *  - escalate: a credential-looking path (`isSecretPath`) wherever it lies,
 *    anywhere outside the session's workspace, and inside it the few places a
 *    write changes what runs or who is trusted (git internals and hooks,
 *    harness and MCP config, env files, CI workflows) and the startup
 *    locations `isSensitiveWriteTarget` names (a shell rc file, anything under
 *    the system's `/etc`, ...), which matter when the workspace is `~`;
 *  - allow: everything else inside the workspace, which is the agent's job.
 *
 * "Where it lands" is judged twice, and the stricter answer wins: by the
 * path's letters, and, on the platform the gate runs on, by where the kernel
 * would write it, every symlink followed (`resolveRealPath`), so a link
 * inside the workspace pointing outside it escalates exactly as its target
 * would.
 */

export type FileWriteVerdict =
  | { decision: "allow" }
  | { decision: "escalate"; reason: string }
  | { decision: "deny"; reason: string };

/** Paths inside a workspace that still need the operator: a write here changes what runs, or who is trusted. */
const SENSITIVE_INSIDE_WORKSPACE: Array<[RegExp, string]> = [
  [/(^|\/)\.git(\/|$)/i, "git's own directory (hooks, config, refs)"],
  [/(^|\/)\.agents(\/|$)/i, "agy's project hooks and settings"],
  [/(^|\/)\.gemini(\/|$)/i, "agy/Gemini configuration"],
  [/(^|\/)\.claude(\/|$)/i, "Claude Code settings and hooks"],
  [/(^|\/)\.opencode(\/|$)/i, "opencode configuration"],
  [/(^|\/)opencode\.jsonc?$/i, "opencode configuration"],
  [/(^|\/)\.mcp\.json$/i, "MCP server configuration"],
  [/(^|\/)\.env(rc|\..*)?$/i, "an environment file"],
  [/(^|\/)\.(github|gitea|forgejo)\/workflows\//i, "a CI workflow, which runs on push"],
  [/(^|\/)\.githooks(\/|$)/i, "git hooks"],
];

/**
 * Why a write to `relative` (a path inside a workspace, relative to its root,
 * forward slashes) needs the operator, or null when it does not. Shared by
 * agy's file tools and OpenCode's, so the two harnesses escalate the same
 * places.
 */
export function sensitiveWorkspaceWrite(relative: string): string | null {
  for (const [pattern, what] of SENSITIVE_INSIDE_WORKSPACE) {
    if (pattern.test(relative)) return what;
  }
  return null;
}

/** Forward slashes, no trailing slash, and case-folded where the filesystem is. */
export function normalizePath(p: string, platform: NodeJS.Platform = process.platform): string {
  const s = p.replace(/\\/g, "/").replace(/\/+$/, "");
  return platform === "win32" ? s.toLowerCase() : s;
}

function isWithin(target: string, root: string): boolean {
  return target === root || target.startsWith(root.endsWith("/") ? root : `${root}/`);
}

/**
 * The verdict for writing `target`. `workspaces` are the session's roots
 * (agy's workspacePaths, OpenCode's directory); with none, nothing can be
 * shown to be inside one, so every write escalates.
 */
export function judgeFileWrite(
  target: string,
  workspaces: string[],
  platform: NodeJS.Platform = process.platform
): FileWriteVerdict {
  if (!target.trim()) {
    return { decision: "escalate", reason: "The file tool named no target file." };
  }
  const pathApi = platform === "win32" ? path.win32 : path.posix;
  // Symlinks can only be followed on the filesystem the gate runs on.
  const native = platform === process.platform;
  const given = workspaces.filter((w) => w.trim());
  const roots = [
    ...new Set([
      ...given.map((w) => normalizePath(pathApi.resolve(w), platform)),
      ...(native ? given.map((w) => normalizePath(resolveRealPath(pathApi.resolve(w)), platform)) : []),
    ]),
  ];
  const relative = !pathApi.isAbsolute(target) && given.length > 0;
  const absolute = relative ? pathApi.join(given[0]!, target) : target;
  const resolved = normalizePath(pathApi.resolve(absolute), platform);
  // Where the kernel would write it: the unfolded join, so `link/..` is the
  // parent of the link's target, as it is for the write itself.
  const joined = relative ? `${given[0]}${pathApi.sep}${target}` : target;
  const landed = native && pathApi.isAbsolute(joined) ? resolveRealPath(joined) : null;
  const locations = [...new Set([resolved, ...(landed ? [normalizePath(landed, platform)] : [])])];

  // Both spellings: a relative path can resolve into the gate's files, and a
  // link can land in them.
  const gate =
    [target, ...locations].some((p) => isProtectedPath(p)) ||
    (native && [absolute, ...(landed ? [landed] : [])].some((p) => isInstallPath(p) || isConfiguredGateFile(p) || isHardLinkToGateFile(p)));
  if (gate) {
    return {
      decision: "deny",
      reason: `Blocked: ${target} belongs to the safety classifier itself, and the agent may not change the gate that judges it. Ask the user to make this change.`,
    };
  }
  // A credential-looking path (a key, a token file, `~/.ssh/...`) needs the
  // operator wherever it lies, inside the workspace too.
  if ([target, ...locations, ...(landed ? [landed] : [])].some((p) => isSecretPath(p))) {
    return { decision: "escalate", reason: `This writes ${target}: a credential-looking path.` };
  }

  const inside: Array<{ loc: string; root: string }> = [];
  for (const loc of locations) {
    const root = roots.find((r) => isWithin(loc, r));
    if (!root) {
      return {
        decision: "escalate",
        reason: `This writes ${target}, outside the session's workspace${roots.length ? ` (${workspaces.join(", ")})` : ""}.`,
      };
    }
    inside.push({ loc, root });
  }
  for (const { loc, root } of inside) {
    const what = sensitiveWorkspaceWrite(loc.slice(root.length).replace(/^\//, ""));
    if (what) return { decision: "escalate", reason: `This writes ${target}: ${what}.` };
  }
  if ([target, ...locations].some((p) => isSensitiveWriteTarget(p))) {
    return { decision: "escalate", reason: `This writes ${target}: a startup location that runs later, outside this session.` };
  }
  return { decision: "allow" };
}
