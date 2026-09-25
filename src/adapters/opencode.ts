import { AutoClassifier } from "../index.js";
import { log } from "../log.js";
import { writeTelemetry } from "../telemetry.js";
import { VERSION } from "../version.js";
import { buildEditExcerpt } from "../classifier/prompt.js";
import type { DecisionOutcome } from "../types.js";
import { isGateDataPath, isGatePath } from "../rules/self-protection.js";
import { timeoutMessage } from "./agy-accept.js";

/** OpenCode's tools that read under a directory rather than write a file. */
const SEARCH_TOOLS = new Set(["grep", "glob", "list"]);

/**
 * The files an OpenCode file tool call would touch: `filePath` for read,
 * edit, write and multiedit, the `path` a grep, glob or list searches under,
 * and every `*** Add/Update/Delete File:` (and `*** Move to:`) line of a patch.
 */
export function fileToolTargets(tool: string, args: unknown): string[] {
  const a = (args ?? {}) as Record<string, unknown>;
  const targets: string[] = [];
  if (typeof a.filePath === "string") targets.push(a.filePath);
  if (SEARCH_TOOLS.has(tool) && typeof a.path === "string" && a.path) targets.push(a.path);
  if (tool === "patch" || tool === "apply_patch") {
    const text = [a.patchText, a.patch, a.input].find((v) => typeof v === "string") as string | undefined;
    for (const m of (text ?? "").matchAll(/^\*\*\* (?:(?:Add|Update|Delete) File|Move to):\s*(.+?)\s*$/gm)) {
      targets.push(m[1]!);
    }
  }
  return targets;
}

interface OpenCodeContext {
  client?: any;
  [key: string]: unknown;
}

/** The permission-reply surface, across the SDK shapes OpenCode has shipped. */
export type PermissionReply = "once" | "always" | "reject";

/**
 * `message` goes with a rejection on the current SDK surface: OpenCode hands it
 * to the model as the operator's feedback and the turn goes on. The legacy
 * route has no field for it.
 */
export async function replyToPermission(client: any, sessionId: string, permissionId: string, reply: PermissionReply, message?: string): Promise<boolean> {
  try {
    if (client?.permission?.reply) {
      await client.permission.reply({ requestID: permissionId, reply, ...(message ? { message } : {}) });
      return true;
    }
    if (client?.postSessionIdPermissionsPermissionId) {
      await client.postSessionIdPermissionsPermissionId({
        path: { id: sessionId, permissionID: permissionId },
        body: { response: reply },
      });
      return true;
    }
  } catch {
    // OpenCode already moved on, or the reply surface changed under us; the prompt stays with the operator.
  }
  return false;
}

/**
 * The text an escalated command carries into the operator's prompt. It goes in
 * two places because OpenCode versions differ in what the prompt shows: as the
 * bash tool's `description` (shown as the prompt's title where supported) and
 * as a leading comment line on the command itself (shown wherever the command
 * text is). A comment changes nothing about what the shell runs.
 */
export function escalationBanner(outcome: DecisionOutcome): string {
  const finding = (outcome.reason ?? "").split("\n").find((l) => l.startsWith("Classifier Finding:")) ?? outcome.reason ?? "";
  const oneLine = finding.replace(/^Classifier Finding:\s*/, "").replace(/[\r\n]+/g, " ");
  // consecutiveCount is only ever nonzero on a repeated-denial escalation --
  // handleDenial always increments it before returning force_ask. A
  // structural refusal (truncated content today; whatever else floors to
  // `ask` without ever having denied the command) carries 0, and "blocked
  // 0x" would be true but backwards: it reads as trivial when the real
  // reason is that the gate could not see the file. Say why instead of
  // asserting a count that doesn't exist on this path.
  const label = outcome.consecutiveCount > 0 ? `blocked ${outcome.consecutiveCount}x` : "cannot evaluate";
  return `construct-auto-classifier ESCALATION (${label}): ${oneLine} -- the agent's own case for running it is in the transcript above`;
}

/**
 * The banner goes onto the command as a leading comment line. The writer
 * (`withBannerComment`) and the stripper (`stripIssuedBanner`) are both built
 * from these two pieces, so the shape cannot drift between them.
 */
const BANNER_LEAD = "# ";
const BANNER_TRAIL = "\n";

/** The command as the operator's prompt should show it: the banner, then the agent's own command. */
export function withBannerComment(banner: string, command: string): string {
  return `${BANNER_LEAD}${banner}${BANNER_TRAIL}${command}`;
}

/**
 * Take back off a command exactly the banner comment this plugin put on it.
 *
 * OpenCode keeps the command we rewrote, so the agent's next attempt at it
 * arrives carrying our own banner: a different string than the one denied, so
 * the gate would not recognise a retry and the banner's text would sit inside
 * the command being judged. Only a line that equals a banner this process
 * issued (`issued`) is removed, a whole leading line and nothing looser. A
 * comment an agent typed in the banner's likeness, or an issued banner with a
 * word changed, matches no issued banner and stays part of the command, so it is
 * judged as text the agent supplied.
 */
export function stripIssuedBanner(command: string, issued: ReadonlySet<string>): string {
  let rest = command;
  while (rest.startsWith(BANNER_LEAD)) {
    const nl = rest.indexOf(BANNER_TRAIL);
    if (nl < 0) break;
    const line = rest.slice(BANNER_LEAD.length, nl).replace(/\r$/, "");
    if (!issued.has(line)) break;
    rest = rest.slice(nl + BANNER_TRAIL.length);
  }
  return rest;
}

/** The description the operator's prompt shows: our banner, then whatever the agent described, never a stale banner of ours. */
function withBannerDescription(banner: string, description: unknown, issued: ReadonlySet<string>): string {
  let rest = typeof description === "string" ? description : "";
  const lead = " | ";
  for (;;) {
    const cut = rest.indexOf(lead);
    const head = cut < 0 ? rest : rest.slice(0, cut);
    if (!issued.has(head)) break;
    rest = cut < 0 ? "" : rest.slice(cut + lead.length);
  }
  return rest ? `${banner}${lead}${rest}` : banner;
}

/** OpenCode's permissions over the tools this plugin gates, in the order a warning names them. */
const GATED_PERMISSIONS = ["bash", "edit", "read", "grep", "glob", "list"];

/** The OpenCode permission that governs `tool`: `edit` covers every tool that writes a file. */
export function permissionKeyFor(tool: string): string {
  return tool === "write" || tool === "patch" || tool === "apply_patch" || tool === "multiedit" ? "edit" : tool;
}

/**
 * What OpenCode's config resolves one permission to, read from the top-level
 * `permission` block the way OpenCode applies it: a string for every tool, or
 * per tool a string or a pattern map whose `"*"` covers a call no other
 * pattern names, falling back to the block's own `"*"` and then to OpenCode's
 * default, "allow". An agent's own `permission` block can override this, and
 * is not read.
 */
export function permissionAction(config: unknown, key: string): unknown {
  const perm = (config as { permission?: unknown } | null | undefined)?.permission;
  if (typeof perm === "string") return perm;
  if (!perm || typeof perm !== "object") return "allow";
  const block = perm as Record<string, unknown>;
  const own = block[key];
  if (typeof own === "string") return own;
  if (own && typeof own === "object" && typeof (own as Record<string, unknown>)["*"] === "string") return (own as Record<string, unknown>)["*"];
  return typeof block["*"] === "string" ? block["*"] : "allow";
}

/**
 * Whether OpenCode's prompt for `key` shows for every call: the permission
 * resolves to "ask", and a pattern map under it names no pattern that would
 * let a call through unasked (only "ask" or "deny" values).
 */
export function permissionAlwaysAsks(config: unknown, key: string): boolean {
  if (permissionAction(config, key) !== "ask") return false;
  const own = ((config as { permission?: unknown } | null | undefined)?.permission as Record<string, unknown> | undefined)?.[key];
  return !own || typeof own !== "object" || Object.values(own as Record<string, unknown>).every((v) => v === "ask" || v === "deny");
}

/**
 * The gated tools' permissions that raise no prompt: anything but "ask" (and
 * "deny", where OpenCode refuses the tool itself). An escalation reaches the
 * operator only through OpenCode's own permission prompt (the plugin answers
 * every prompt the gate settles, and leaves an escalation's up), so the
 * plugin refuses an escalation on each tool named here instead of letting it
 * run unasked. OpenCode's default is "allow" for all of them.
 */
export function permissionsWithoutPrompt(config: unknown): string[] {
  return GATED_PERMISSIONS.filter((key) => {
    const action = permissionAction(config, key);
    return action !== "ask" && action !== "deny";
  });
}

export function createOpenCodePlugin(customClassifier?: AutoClassifier) {
  // Built lazily so importing this module (or the bundled plugin) never reads
  // config or touches the state directory until OpenCode first calls a hook.
  let classifier: AutoClassifier | undefined = customClassifier;
  const getClassifier = (): AutoClassifier => (classifier ??= new AutoClassifier());
  const decisions = new Map<string, DecisionOutcome>();
  // Every banner this process has written, so the ones handed back to us can be
  // told from a lookalike an agent typed. In memory: after a restart an old
  // banner is unrecognised and judged as written, which is the safe direction.
  const issuedBanners = new Set<string>();
  // OpenCode's resolved config, from its `config` hook; undefined until it arrives.
  let openCodeConfig: unknown;
  let configSeen = false;

  /**
   * Whether OpenCode will put a prompt in front of the operator for `tool`:
   * only when its permission resolves to "ask". Before the config arrives,
   * bash and edit keep their documented setup (step 2 of the README makes
   * "ask" a required step, and the startup warning names it), while read and
   * the search tools, whose default raises no prompt, are taken to have none.
   */
  const promptReaches = (tool: string): boolean => {
    const key = permissionKeyFor(tool);
    if (!configSeen) return key === "bash" || key === "edit";
    return permissionAction(openCodeConfig, key) === "ask";
  };

  return function autoClassifierPlugin(ctx: OpenCodeContext) {
    /**
     * The directory a session's commands run in.
     *
     * `output.args.workdir` is set only when the agent passed one. Without it
     * the gate would judge the command in the plugin process's cwd -- where the
     * OpenCode SERVER was started, which is not necessarily the session's
     * project (a server launched with no working directory runs in `/`). A
     * `git push origin` judged in the wrong directory resolves the wrong remote,
     * or none, and an unresolvable remote is refused, so the agent is falsely
     * denied. OpenCode keeps the truth on the session, so read it once and cache
     * it. Every
     * failure path falls back to the directory this plugin was handed.
     */
    const sessionDirs = new Map<string, string | undefined>();
    const sessionDirectory = async (sessionId: string): Promise<string | undefined> => {
      if (!sessionId) return undefined;
      if (sessionDirs.has(sessionId)) return sessionDirs.get(sessionId);
      let dir: string | undefined;
      try {
        const response = await ctx?.client?.session?.get({ path: { id: sessionId } });
        const d = response?.data?.directory;
        if (typeof d === "string" && d) dir = d;
      } catch {
        // An SDK shape without session.get, or a session that is already gone.
      }
      if (!dir && typeof ctx?.directory === "string" && ctx.directory) dir = ctx.directory;
      if (!dir && typeof ctx?.worktree === "string" && ctx.worktree) dir = ctx.worktree;
      sessionDirs.set(sessionId, dir);
      if (sessionDirs.size > 200) {
        const first = sessionDirs.keys().next().value;
        if (first) sessionDirs.delete(first);
      }
      return dir;
    };

    /**
     * Common tail for both the bash and file-tool branches: remember the
     * verdict by callID (the `event` hook's primary lookup for either kind
     * of call), log it, throw on deny, and throw on ask/force_ask when the
     * machine is headless or the tool raises no prompt (`promptReaches`) --
     * either way nobody is at a prompt to answer it, and a call that is not
     * refused here simply runs. An escalation the gate raised (`gateRaised`)
     * also throws under an allow pattern (`permissionAlwaysAsks`), and a
     * rule's refusal before OpenCode's config arrives.
     */
    const recordAndEnforce = (tool: string, callId: string, label: string, outcome: DecisionOutcome) => {
      log(`${outcome.decision} ${callId} ${label}${outcome.decision === "allow" ? "" : ` -- ${(outcome.reason ?? "").slice(0, 160)}`}`);
      if (callId) {
        decisions.set(callId, outcome);
        if (decisions.size > 200) {
          const first = decisions.keys().next().value;
          if (first) decisions.delete(first);
        }
      }

      if (outcome.decision === "deny") {
        // Throwing in tool.execute.before returns the reason to the model
        throw new Error(outcome.reason);
      }

      if (outcome.decision === "force_ask" || outcome.decision === "ask") {
        const headless = getClassifier().getConfig().policy.headless;
        if (headless) {
          // Nobody is at the prompt. Say so to the agent instead of leaving a
          // permission pending forever (or letting `opencode run` auto-reject
          // it as if the operator had declined).
          throw new Error(
            `${outcome.reason}\n` +
              `This machine is headless: nobody can answer a prompt here. Stop, and report to the user that this command needs their decision.`
          );
        }
        if (!promptReaches(tool)) {
          throw new Error(
            `${outcome.reason}\n` +
              `No permission prompt reaches the user for OpenCode's ${tool} tool (its permission is not "ask"), so this call cannot wait for their approval. Stop, and ask the user to approve it or to do it themselves.`
          );
        }
        // An escalation the gate raised (a rule's refusal, an escalated write, a
        // script cut short, or a model that could not be reached) had no
        // model's judgement behind it, so it is refused when a pattern under
        // the tool's permission lets calls through unasked. A rule's refusal
        // waits only on a prompt that is sure to show, so it is refused too
        // until OpenCode's config has arrived.
        const unsure = configSeen ? !permissionAlwaysAsks(openCodeConfig, permissionKeyFor(tool)) : outcome.ruleRefusal === true;
        if (outcome.gateRaised && unsure) {
          throw new Error(
            `${outcome.reason}\n` +
              `The gate itself raised this for the user to decide, not a model's judgement, and OpenCode's permission prompt for its ${tool} tool may not show (${configSeen ? "a pattern under that permission lets calls through unasked" : "OpenCode's config has not reached the plugin yet"}), so only the user can decide it. Stop, and ask the user to approve it or to do it themselves.`
          );
        }
      }
    };

    return {
      name: "construct-auto-classifier",
      version: VERSION,

      // OpenCode hands every plugin its resolved config once, at startup.
      async config(cfg: unknown) {
        openCodeConfig = cfg;
        configSeen = true;
        const noPrompt = permissionsWithoutPrompt(cfg);
        const names = (tools: string[]) => tools.map((t) => `"${t}"`).join(", ");
        const required = noPrompt.filter((t) => t === "bash" || t === "edit");
        const rest = noPrompt.filter((t) => t !== "bash" && t !== "edit");
        if (required.length) {
          log(
            `WARNING: OpenCode's permission for ${names(required)} is not "ask", so an escalation the gate raises there cannot reach you: the gate refuses the call and tells the agent to ask you. ` +
              `Set "permission": { "bash": "ask", "edit": "ask" } in opencode.json: the gate answers every prompt it settles, so only its escalations reach you.`
          );
        }
        if (rest.length) {
          log(
            `note: OpenCode's permission for ${names(rest)} is not "ask", so the gate refuses an escalation on ${rest.length > 1 ? "those tools" : "that tool"} and tells the agent to ask you. Set ${rest.length > 1 ? "them" : "it"} to "ask" to be prompted instead.`
          );
        }
      },

      // Intercept tool execution before execution
      async "tool.execute.before"(input: any, output: any) {
        if (!input) {
          return;
        }

        // Self-protection for every non-bash tool: OpenCode's own file tools
        // write without a shell command, so the shell rules never see them, and
        // the one thing they may never touch is the gate itself -- the same
        // protected set a redirect is refused for. This does NOT return: the
        // tool's own branch below still runs, and carries the same
        // protected-path deny for read/write/edit/patch.
        if (input.tool !== "bash") {
          const workspace = typeof ctx?.directory === "string" && ctx.directory ? ctx.directory : undefined;
          for (const target of fileToolTargets(input.tool, output?.args)) {
            // Reading or searching the gate's code is harmless; reading its
            // config or state is refused like any other touch of it. Both are
            // judged on the path as written and on where it lands, so a
            // symlink (or hard link) to the gate is the gate.
            if (input.tool === "read" || SEARCH_TOOLS.has(input.tool) ? isGateDataPath(target, workspace) : isGatePath(target, workspace)) {
              log(`deny ${input.callID || ""} ${input.tool} ${target} -- self-protection`);
              writeTelemetry(getClassifier().getConfig().telemetry, {
                id: input.callID || "",
                session: input.sessionID || "opencode-session",
                command: `${input.tool} ${target}`,
                file_path: target,
                file_snippet: null,
                decision: "deny",
                source: "protected-deny",
                reason: "the target belongs to the safety classifier itself",
                latency_ms: 0,
                model: null,
                injection_attempt: false,
                injection_pattern: null,
                cwd: workspace ?? null,
                tool: input.tool,
              });
              throw new Error(
                `Blocked: ${target} belongs to the safety classifier itself -- the classifier's own gate, which the agent may not change. Ask the user to make this change.`
              );
            }
          }
        }

        if (input.tool === "bash") {
          const rawCommand = output?.args?.command || input?.parameters?.command;
          if (!rawCommand || typeof rawCommand !== "string" || rawCommand.length === 0) {
            return;
          }
          // The gate judges the agent's own command, never our banner handed back.
          const command = stripIssuedBanner(rawCommand, issuedBanners);

          const sessionId = input.sessionID || "opencode-session";
          const callId = input.callID || "";

          const cwd = (typeof output?.args?.workdir === "string" && output.args.workdir) || (await sessionDirectory(sessionId));
          const outcome: DecisionOutcome = await getClassifier().evaluate(command, sessionId, undefined, { cwd, callId });
          recordAndEnforce("bash", callId, `"${command.slice(0, 120).replace(/\n/g, " ")}"`, outcome);

          if ((outcome.decision === "force_ask" || outcome.decision === "ask") && output?.args && typeof output.args === "object") {
            // Carry the finding into the operator's prompt. File tools have
            // no equivalent text field their permission UI renders (their
            // args are `filePath`/`content`/`oldString`/`newString`, not a
            // command line with room for a leading comment), so this banner
            // stays bash-only; a file-tool ask/force_ask still reaches the
            // operator, just without the embedded finding.
            const banner = escalationBanner(outcome);
            issuedBanners.add(banner);
            if (issuedBanners.size > 200) {
              const first = issuedBanners.values().next().value;
              if (first) issuedBanners.delete(first);
            }
            output.args.description = withBannerDescription(banner, output.args.description, issuedBanners);
            output.args.command = withBannerComment(banner, command);
          }
          return;
        }

        if (input.tool === "read" || input.tool === "write" || input.tool === "edit") {
          // At the `before` phase OpenCode carries a file tool's own args on
          // THIS argument (`output.args`), not `input.args`.
          const filePath = output?.args?.filePath;
          if (typeof filePath !== "string" || !filePath) return;

          const sessionId = input.sessionID || "opencode-session";
          const callId = input.callID || "";
          const cwd = typeof ctx?.directory === "string" && ctx.directory ? ctx.directory : undefined;

          const content =
            input.tool === "write"
              ? typeof output?.args?.content === "string"
                ? output.args.content
                : ""
              : buildEditExcerpt(typeof output?.args?.oldString === "string" ? output.args.oldString : "", typeof output?.args?.newString === "string" ? output.args.newString : "");

          const outcome = await getClassifier().evaluateFileOp(input.tool, filePath, sessionId, input.tool === "read" ? undefined : content, { cwd, callId });
          recordAndEnforce(input.tool, callId, filePath, outcome);
          return;
        }

        if (input.tool === "grep" || input.tool === "glob" || input.tool === "list") {
          // Each of these takes an optional `path` scoping a recursive walk;
          // an omitted one defaults to the session's own active location
          // (OpenCode's own tool description). The classifier decides which
          // scopes are routine and which sweep up a credential directory.
          const searchPath = typeof output?.args?.path === "string" && output.args.path ? output.args.path : undefined;
          const sessionId = input.sessionID || "opencode-session";
          const callId = input.callID || "";
          const cwd = typeof ctx?.directory === "string" && ctx.directory ? ctx.directory : undefined;

          const pattern = typeof output?.args?.pattern === "string" && output.args.pattern ? output.args.pattern : undefined;
          const outcome = await getClassifier().evaluateSearchScope(input.tool, searchPath, sessionId, { cwd, callId, pattern });
          recordAndEnforce(input.tool, callId, searchPath ?? "(active location)", outcome);
          return;
        }

        if (input.tool === "patch" || input.tool === "apply_patch") {
          // OpenCode's own registered tool id is "apply_patch" (confirmed via
          // `strings` on the installed binary: `j("apply_patch", ...)`,
          // `name:()=>zP` where `zP="apply_patch"`); some of its own internal
          // routing also checks a `"patch"` alias, so both are accepted here
          // rather than risk missing the one OpenCode's plugin host actually
          // dispatches under.
          const patchText = output?.args?.patchText;
          if (typeof patchText !== "string" || !patchText) return;

          const sessionId = input.sessionID || "opencode-session";
          const callId = input.callID || "";
          const cwd = typeof ctx?.directory === "string" && ctx.directory ? ctx.directory : undefined;

          const outcome = await getClassifier().evaluatePatch(patchText, sessionId, { cwd, callId });
          recordAndEnforce(input.tool, callId, "patch", outcome);
          return;
        }
      },

      // Handle interactive permissions event
      event: async (input: any) => {
        const evt = input?.event;
        if (!evt || evt.type !== "permission.asked") {
          return;
        }

        const props = evt.properties || {};
        const sessionId = props.sessionID || "opencode-session";
        const permissionId = props.id;
        const callId = props.callID || props.tool?.callID;
        const askedCommand = props.metadata?.command || "";
        const command = typeof askedCommand === "string" ? stripIssuedBanner(askedCommand, issuedBanners) : "";

        let outcome = callId ? decisions.get(callId) : undefined;
        if (!outcome && command) {
          outcome = await getClassifier().evaluate(command, sessionId, undefined, { cwd: await sessionDirectory(sessionId) });
        }
        if (callId) {
          decisions.delete(callId);
        }

        if (outcome?.decision === "allow") {
          await replyToPermission(ctx.client, sessionId, permissionId, "once");
        } else if (outcome?.decision === "deny") {
          await replyToPermission(ctx.client, sessionId, permissionId, "reject");
        } else if (outcome?.decision === "ask" || outcome?.decision === "force_ask") {
          const timeoutMinutes = getClassifier().getConfig().policy.escalationTimeoutMinutes ?? 5;
          const timeoutMs = timeoutMinutes * 60 * 1000;
          const timer = setTimeout(async () => {
            log(`opencode: permission ${permissionId} timed out after ${timeoutMinutes}m`);
            // The explanation rides on the rejection itself. No timeout record:
            // only agy's PreInvocation hook reads those, and its fallback to
            // the newest record would hand this one to an unrelated agy session.
            await replyToPermission(ctx.client, sessionId, permissionId, "reject", timeoutMessage({ kind: "command", command }, timeoutMinutes));
          }, timeoutMs);
          if (timer.unref) timer.unref();
        }
      },
    };
  };
}

export default createOpenCodePlugin();
