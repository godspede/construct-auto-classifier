import * as path from "node:path";
import { isProtectedPath } from "./self-protection.js";

/**
 * Judging an agent's file-writing tool call (agy's write_to_file /
 * replace_file_content, opencode's edit / write / patch), where the harness
 * hands over a target path and there is no shell command to classify.
 *
 * Deterministic and model-free, because a file write's risk is almost all in
 * where it lands:
 *  - deny: the gate's own files (config, log, plugin, session state), the
 *    same set the shell rules protect, so an edit tool cannot do what a
 *    redirect may not;
 *  - escalate: anywhere outside the session's workspace, and inside it the
 *    few places a write changes what runs or who is trusted (git internals and
 *    hooks, harness and MCP config, env files, CI workflows);
 *  - allow: everything else inside the workspace, which is the agent's job.
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
 * (agy's workspacePaths, opencode's directory); with none, nothing can be
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
  const roots = workspaces.filter((w) => w.trim()).map((w) => normalizePath(pathApi.resolve(w), platform));
  const absolute = pathApi.isAbsolute(target) || roots.length === 0 ? target : pathApi.join(workspaces[0]!, target);
  const resolved = normalizePath(pathApi.resolve(absolute), platform);

  // Both spellings: a relative path can resolve into the gate's files.
  if (isProtectedPath(target) || isProtectedPath(resolved)) {
    return {
      decision: "deny",
      reason: `Blocked: ${target} belongs to the safety classifier itself, and the agent may not change the gate that judges it. Ask the operator to make this change.`,
    };
  }

  const root = roots.find((r) => isWithin(resolved, r));
  if (!root) {
    return {
      decision: "escalate",
      reason: `This writes ${target}, outside the session's workspace${roots.length ? ` (${workspaces.join(", ")})` : ""}.`,
    };
  }
  const relative = resolved.slice(root.length).replace(/^\//, "");
  for (const [pattern, what] of SENSITIVE_INSIDE_WORKSPACE) {
    if (pattern.test(relative)) {
      return { decision: "escalate", reason: `This writes ${target}: ${what}.` };
    }
  }
  return { decision: "allow" };
}
