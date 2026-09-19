/**
 * The exact opencode payload shapes the plugin's two hooks receive, built
 * from one definition so bench/run.ts and tests/battery-fidelity.test.ts can
 * never drift from each other -- or from the adapter they both drive.
 *
 * `beforeHookFieldsRead` / `eventHookFieldsRead` read the fields back out of
 * the adapter's own source (src/adapters/opencode.ts) rather than a
 * hand-maintained list, so a field the adapter starts or stops touching
 * changes what these payloads are checked against with nothing here to keep
 * in sync by hand.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const ADAPTER_SOURCE_PATH = path.join(here, "..", "src", "adapters", "opencode.ts");

export function readAdapterSource(): string {
  return fs.readFileSync(ADAPTER_SOURCE_PATH, "utf-8");
}

/** The `{ ... }` block that follows the first occurrence of `startNeedle`, by brace counting. */
function extractBlock(src: string, startNeedle: string): string {
  const start = src.indexOf(startNeedle);
  if (start === -1) {
    throw new Error(`opencode.ts no longer contains ${JSON.stringify(startNeedle)} -- update this extraction`);
  }
  const braceStart = src.indexOf("{", start);
  let depth = 0;
  for (let i = braceStart; i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}") {
      depth--;
      if (depth === 0) return src.slice(braceStart, i + 1);
    }
  }
  throw new Error(`unbalanced braces reading the block starting at ${JSON.stringify(startNeedle)}`);
}

const CHAIN_SUFFIX = "((?:\\??\\.[A-Za-z0-9_]+)+)";

/** Every `root.a?.b.c` access rooted at one of `rootAlt` (a `|`-joined alternation), as the dotted path after the root. */
function extractAccesses(block: string, rootAlt: string): string[] {
  const re = new RegExp("\\b(?:" + rootAlt + ")\\b" + CHAIN_SUFFIX, "g");
  const out = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = re.exec(block)) !== null) {
    out.add(m[1].split("?").join("").slice(1));
  }
  return [...out];
}

/**
 * Accesses the extraction above finds that are containers, local aliases, or
 * routing discriminants rather than a leaf field the verdict is computed
 * from -- filtering these out (instead of hand-listing the fields kept) is
 * what lets the remainder be asserted as ground truth pulled from the
 * source, rather than a second copy of the contract:
 *
 * - `event`, `properties`: `evt`/`props` are the adapter's own local names
 *   for `input.event` / `evt.properties`; a bare access to the whole
 *   sub-object is not a distinct field once its own contents are read
 *   through `evt`/`props` directly (as the extraction below already does).
 * - `type`: `evt.type` is "is this a `permission.asked` event", not data the
 *   classifier's verdict depends on.
 * - `args`: `output?.args && typeof output.args === "object"` is the same
 *   kind of routing check on the before-hook side.
 * - `parameters.command`: a secondary OR-fallback
 *   (`output?.args?.command || input?.parameters?.command`) the battery's
 *   payload never needs to hit, because `output.args.command` is always
 *   populated in what opencode actually sends.
 * - `args.description`: mutated to carry the escalation banner into the
 *   operator's prompt, but never read to decide a verdict.
 */
const NOT_A_VERDICT_FIELD = new Set(["event", "properties", "type", "args", "parameters.command", "args.description"]);

/** Fields `tool.execute.before` reads off its `(input, output)` pair to decide a verdict. */
export function beforeHookFieldsRead(src = readAdapterSource()): string[] {
  const block = extractBlock(src, 'async "tool.execute.before"');
  return extractAccesses(block, "input|output").filter((f) => !NOT_A_VERDICT_FIELD.has(f));
}

/** Fields the `event` hook reads off its `permission.asked` payload to decide a verdict. */
export function eventHookFieldsRead(src = readAdapterSource()): string[] {
  const block = extractBlock(src, "event: async (input: any)");
  return extractAccesses(block, "evt|props|input").filter((f) => !NOT_A_VERDICT_FIELD.has(f));
}

/** Flatten an object into dotted leaf paths, e.g. `{a: {b: 1}}` -> `["a.b"]`. */
export function flattenPaths(obj: unknown, prefix = ""): string[] {
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) return prefix ? [prefix] : [];
  const out: string[] = [];
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    const p = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === "object" && !Array.isArray(v)) out.push(...flattenPaths(v, p));
    else out.push(p);
  }
  return out;
}

/** True if `field` names, or is the final segment of, some path in `paths` -- payload objects nest fields under a fixed JS shape the adapter's own alias names collapse away, so an exact-string match would fight that nesting instead of checking the fields that matter. */
export function coversField(paths: string[], field: string): boolean {
  return paths.some((p) => p === field || p.endsWith("." + field));
}

// -------------------------------------------------------------------------
// Payload builders. These are the ONLY place the battery (bench/run.ts) and
// the fidelity test (tests/battery-fidelity.test.ts) construct an opencode
// payload -- so a shape either of them drives is a shape they both drive.
// -------------------------------------------------------------------------

export interface CaseIdentity {
  sessionId: string;
  callId: string;
}

/** `tool.execute.before`'s first argument, exactly as opencode builds it for a bash tool call. */
export function beforeHookInput(id: CaseIdentity): { tool: string; sessionID: string; callID: string } {
  return { tool: "bash", sessionID: id.sessionId, callID: id.callId };
}

/** `tool.execute.before`'s second, mutable argument: the tool call's own output/args object. */
export function beforeHookOutput(command: string, cwd?: string): { args: { command: string; workdir?: string } } {
  return cwd ? { args: { command, workdir: cwd } } : { args: { command } };
}

/**
 * The `event` hook's argument for a `permission.asked` event.
 *
 * `shape` picks which of the two places opencode has shipped `callID` under
 * `properties` -- the adapter reads `props.callID || props.tool?.callID`, and
 * `opencode-adapter.test.ts`'s own `asked()` helper (this repo's existing
 * template for driving the real adapter) defaults to the nested one, so this
 * does too.
 */
export function permissionAskedEvent(
  id: CaseIdentity,
  permissionId: string,
  command: string,
  shape: "flat" | "nested" = "nested"
): { event: { type: "permission.asked"; properties: Record<string, unknown> } } {
  const properties: Record<string, unknown> = { id: permissionId, sessionID: id.sessionId, metadata: { command } };
  if (shape === "flat") properties.callID = id.callId;
  else properties.tool = { callID: id.callId };
  return { event: { type: "permission.asked", properties } };
}
