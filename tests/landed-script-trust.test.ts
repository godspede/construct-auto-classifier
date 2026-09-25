import { describe, it, expect } from "bun:test";
import { findScriptInvocation } from "../src/context/script-provenance.js";
import { AutoClassifier } from "../src/index.js";
import { StateManager } from "../src/state/state-manager.js";
import { FakeLlm } from "./helpers/fake-llm.js";
import { tmpStateDir } from "./helpers/tmp-state.js";
import { testConfig } from "./helpers/config.js";
import { gitFixture } from "./helpers/git-fixture.js";

/**
 * Landed-script trust is the narrowest shape only: the whole line is one
 * simple command whose verb is the script's own path, or a bare interpreter
 * name (resolved from PATH, never a path) followed straight by the script,
 * with no env assignment, no redirect of any kind, no other segment, no
 * `source`/`.`, no interpreter flag, and arguments free of shell
 * metacharacters and of credential-looking paths. Anything else is still a
 * script run -- its content goes to the model -- but is never allowed for
 * being landed.
 *
 * Every command string in this file is data handed to the gate. None is ever run.
 */

function build(llm: FakeLlm) {
  const config = testConfig();
  const state = new StateManager(config.policy.slidingWindowMs, config.policy.consecutiveThreshold, tmpStateDir());
  return new AutoClassifier(config, { classifier: llm, stateManager: state });
}

describe("the narrow shape is trusted without the model", () => {
  for (const line of [
    "./deploy/publish.sh",
    "./deploy/publish.sh --dry-run v1.2.3",
    "./deploy/publish.sh --target=staging key=value",
    "bash ./deploy/publish.sh",
    "bash deploy/publish.sh",
    "sh deploy/publish.sh --verbose",
  ]) {
    it(`\`${line}\``, async () => {
      const f = gitFixture();
      const llm = new FakeLlm();
      const out = await build(llm).evaluate(line, "s", undefined, { cwd: f.work });
      expect(out.decision).toBe("allow");
      expect(out.reason).toContain("Landed script");
      expect(llm.calls.length).toBe(0);
    });
  }
});

describe("every other run of a landed script goes to the model", () => {
  for (const line of [
    // A pipe into an "output shaper" that opens its own file.
    "./deploy/publish.sh | cat /etc/shadow",
    "./deploy/publish.sh | grep root /etc/shadow",
    "./deploy/publish.sh | wc -l /etc/shadow",
    "./deploy/publish.sh | head -5 ~/.ssh/id_rsa",
    "./deploy/publish.sh | sudo cat /etc/shadow",
    "./deploy/publish.sh | tail -3",
    "./deploy/publish.sh 2>&1 | tail -15",
    // An interpreter named by path is not the reviewed bytes.
    "./bin/bash ./deploy/publish.sh",
    "/tmp/evil/bash ./deploy/publish.sh",
    "./bin/python ./deploy/publish.sh",
    "/usr/bin/bash ./deploy/publish.sh",
    // Source, input redirects, here-strings, here-documents.
    "source ./deploy/publish.sh",
    ". ./deploy/publish.sh",
    "./deploy/publish.sh <<< payload",
    "./deploy/publish.sh < /etc/shadow",
    "./deploy/publish.sh<in.txt",
    "./deploy/publish.sh <<EOF\npayload\nEOF",
    // Interpreter flags.
    "bash --rcfile /tmp/x ./deploy/publish.sh",
    "bash -O extglob ./deploy/publish.sh",
    "bash -i ./deploy/publish.sh",
    "bash -x ./deploy/publish.sh",
    "pwsh -File deploy/publish.sh",
    // Any redirect at all, output included.
    "./deploy/publish.sh 2>&1",
    "./deploy/publish.sh > /dev/null",
    "./deploy/publish.sh>/tmp/out.txt",
    // Any other segment.
    "./deploy/publish.sh; id",
    "./deploy/publish.sh && id",
    "./deploy/publish.sh || id",
    "./deploy/publish.sh & id",
    "id; ./deploy/publish.sh",
    // Env, privilege, wrappers.
    "X=1 ./deploy/publish.sh",
    "sudo ./deploy/publish.sh",
    "sudo bash ./deploy/publish.sh",
    "nice ./deploy/publish.sh",
    // Arguments carrying shell metacharacters or naming a credential.
    "./deploy/publish.sh 'a b'",
    './deploy/publish.sh "$HOME"',
    "./deploy/publish.sh $HOME",
    "./deploy/publish.sh *",
    "./deploy/publish.sh ~/.ssh/id_rsa",
    "./deploy/publish.sh /etc/shadow",
    "./deploy/publish.sh /home/dev/.aws/credentials",
    "./deploy/publish.sh a\\;id",
  ]) {
    it(`\`${line.replace(/\n/g, "\\n")}\``, async () => {
      const f = gitFixture();
      const llm = new FakeLlm([], { allow: false, reason: "not the reviewed run" });
      const out = await build(llm).evaluate(line, "s", undefined, { cwd: f.work });
      expect(out.reason ?? "").not.toContain("Landed script");
      expect(out.decision).toBe("deny");
    });
  }

  it("a cd prefix is another segment", async () => {
    const f = gitFixture();
    const llm = new FakeLlm([], { allow: false, reason: "not the reviewed run" });
    const out = await build(llm).evaluate(`cd ${f.work} && ./deploy/publish.sh`, "s", undefined, { cwd: "/" });
    expect(out.decision).toBe("deny");
    expect(llm.calls.length).toBe(1);
  });

  it("a non-plain run still shows the model the script's content and provenance", async () => {
    const f = gitFixture();
    const llm = new FakeLlm([], { allow: false, reason: "no" });
    await build(llm).evaluate("./deploy/publish.sh | cat /etc/shadow", "s", undefined, { cwd: f.work });
    const ctx = llm.calls[0]?.fileContext as { content: string; provenance: string };
    expect(ctx.provenance).toContain("byte-identical");
    expect(ctx.content).toContain("echo publish");
  });
});

describe("findScriptInvocation: plain means the narrow shape", () => {
  it("is plain only for the script's own path or a bare interpreter then the script", () => {
    expect(findScriptInvocation("./deploy/publish.sh")?.plain).toBe(true);
    expect(findScriptInvocation("bash scripts/build.sh --release")?.plain).toBe(true);
    expect(findScriptInvocation("python3 tools/migrate.py --dry-run")?.plain).toBe(true);
    expect(findScriptInvocation("sudo python3 tools/migrate.py --dry-run")?.plain).toBe(false);
    expect(findScriptInvocation("/srv/app/.venv/bin/python tools/gen.py --out x")?.plain).toBe(false);
    expect(findScriptInvocation("/usr/local/bin/node scripts/build.js")?.plain).toBe(false);
    expect(findScriptInvocation("./bin/bash ./deploy/run.sh")?.plain).toBe(false);
    expect(findScriptInvocation("pwsh -File deploy/push.ps1")?.plain).toBe(false);
    expect(findScriptInvocation("cd /srv && ./deploy/run.sh")?.plain).toBe(false);
  });
});
