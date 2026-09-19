import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { AutoClassifier } from "../index.js";
import { log } from "../log.js";
import { VERSION } from "../version.js";
import type { DecisionOutcome } from "../types.js";
import { isProtectedPath } from "../rules/self-protection.js";

/**
 * The files an opencode file tool call would write: `filePath` for edit,
 * write and multiedit, and every `*** Add/Update/Delete File:` (and
 * `*** Move to:`) line of a patch.
 */
export function fileToolTargets(tool: string, args: unknown): string[] {
  const a = (args ?? {}) as Record<string, unknown>;
  const targets: string[] = [];
  if (typeof a.filePath === "string") targets.push(a.filePath);
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

/** The permission-reply surface, across the SDK shapes opencode has shipped. */
export type PermissionReply = "once" | "always" | "reject";

export async function replyToPermission(client: any, sessionId: string, permissionId: string, reply: PermissionReply): Promise<boolean> {
  try {
    if (client?.permission?.reply) {
      await client.permission.reply({ requestID: permissionId, reply });
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
    // opencode already moved on, or the reply surface changed under us; the prompt stays with the operator.
  }
  return false;
}

/**
 * The text an escalated command carries into the operator's prompt. It goes in
 * two places because opencode versions differ in what the prompt shows: as the
 * bash tool's `description` (shown as the prompt's title where supported) and
 * as a leading comment line on the command itself (shown wherever the command
 * text is). A comment changes nothing about what the shell runs.
 */
export function escalationBanner(outcome: DecisionOutcome): string {
  const finding = (outcome.reason ?? "").split("\n").find((l) => l.startsWith("Classifier Finding:")) ?? outcome.reason ?? "";
  const oneLine = finding.replace(/^Classifier Finding:\s*/, "").replace(/[\r\n]+/g, " ");
  return `construct-auto-classifier ESCALATION (blocked ${outcome.consecutiveCount}x): ${oneLine} -- the agent's own case for running it is in the transcript above`;
}

/** Other opencode plugins known to answer `permission.asked` themselves. */
const SIBLING_GATES = ["auto-mode.js"];

export function detectSiblingGates(pluginsDir = path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config"), "opencode", "plugins")): string[] {
  try {
    return SIBLING_GATES.filter((f) => fs.existsSync(path.join(pluginsDir, f)));
  } catch {
    return [];
  }
}

export interface OpenCodePluginOptions {
  /** Where to look for sibling gates; tests point this at a temp dir. */
  pluginsDir?: string;
}

export function createOpenCodePlugin(customClassifier?: AutoClassifier, options: OpenCodePluginOptions = {}) {
  // Built lazily so importing this module (or the bundled plugin) never reads
  // config or touches the state directory until opencode first calls a hook.
  let classifier: AutoClassifier | undefined = customClassifier;
  const getClassifier = (): AutoClassifier => (classifier ??= new AutoClassifier());
  const decisions = new Map<string, DecisionOutcome>();
  let warnedAboutSiblings = false;

  const warnAboutSiblings = () => {
    if (warnedAboutSiblings) return;
    warnedAboutSiblings = true;
    const siblings = detectSiblingGates(options.pluginsDir);
    if (siblings.length > 0) {
      const msg =
        `another command gate is installed beside this plugin (${siblings.join(", ")}). ` +
        `Both answer opencode's permission prompt, so an escalation this plugin leaves for the operator ` +
        `can be rejected by the other before anyone sees it. Keep one gate.`;
      log(`WARNING: ${msg}`);
      console.error(`[auto-classifier] ${msg}`);
    }
  };

  return function autoClassifierPlugin(ctx: OpenCodeContext) {
    return {
      name: "construct-auto-classifier",
      version: VERSION,

      // Intercept tool execution before execution
      async "tool.execute.before"(input: any, output: any) {
        if (!input) {
          return;
        }
        // opencode's own file tools write without a shell command, so the
        // shell rules never see them. The one thing they may never touch is
        // the gate itself: the same protected set a redirect is refused for.
        if (input.tool !== "bash") {
          for (const target of fileToolTargets(input.tool, output?.args)) {
            if (isProtectedPath(target)) {
              log(`deny ${input.callID || ""} ${input.tool} ${target} -- self-protection`);
              throw new Error(
                `Blocked: ${target} belongs to the safety classifier itself, and the agent may not change the gate that judges it. Ask the operator to make this change.`
              );
            }
          }
          return;
        }

        const command = output?.args?.command || input?.parameters?.command;
        if (!command || typeof command !== "string" || command.length === 0) {
          return;
        }
        warnAboutSiblings();

        const sessionId = input.sessionID || "opencode-session";
        const callId = input.callID || "";

        const cwd = typeof output?.args?.workdir === "string" && output.args.workdir ? output.args.workdir : undefined;
        const outcome: DecisionOutcome = await getClassifier().evaluate(command, sessionId, undefined, { cwd, callId });
        log(`${outcome.decision} ${callId} "${command.slice(0, 120).replace(/\n/g, " ")}"${outcome.decision === "allow" ? "" : ` -- ${(outcome.reason ?? "").slice(0, 160)}`}`);
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
                `This box is headless: no operator can answer a prompt here. Stop, and report to the operator that this command needs their decision.`
            );
          }
          // Carry the finding into the operator's prompt.
          if (output?.args && typeof output.args === "object") {
            const banner = escalationBanner(outcome);
            output.args.description = output.args.description ? `${banner} | ${output.args.description}` : banner;
            output.args.command = `# ${banner}\n${command}`;
          }
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
        const rawCommand = props.metadata?.command || "";
        const command = typeof rawCommand === "string" ? rawCommand.replace(/^# construct-auto-classifier ESCALATION[^\n]*\n/, "") : "";

        let outcome = callId ? decisions.get(callId) : undefined;
        if (!outcome && command) {
          outcome = await getClassifier().evaluate(command, sessionId);
        }
        if (callId) {
          decisions.delete(callId);
        }

        if (outcome?.decision === "allow") {
          await replyToPermission(ctx.client, sessionId, permissionId, "once");
        } else if (outcome?.decision === "deny") {
          await replyToPermission(ctx.client, sessionId, permissionId, "reject");
        }
        // If outcome.decision === "ask" | "force_ask", do nothing so OpenCode presents the prompt to user
      },
    };
  };
}

export default createOpenCodePlugin();
