import { describe, it, expect } from "bun:test";
import { StateManager } from "../src/state/state-manager.js";
import { tmpStateDir } from "./helpers/tmp-state.js";

function manager(threshold = 3, windowMs = 300000) {
  let t = 1_000_000;
  const m = new StateManager(windowMs, threshold, tmpStateDir(), () => t);
  return { m, advance: (ms: number) => (t += ms) };
}
const sid = () => "s-" + Math.random().toString(36).slice(2);

describe("StateManager: denials are counted per command", () => {
  it("escalates on the threshold-th denial of the same command", () => {
    const { m } = manager(3);
    const s = sid();
    expect(m.recordDenial(s, "rm -rf /var", "destructive")).toEqual({ consecutiveCount: 1, escalated: false });
    expect(m.recordDenial(s, "rm -rf /var", "destructive")).toEqual({ consecutiveCount: 2, escalated: false });
    expect(m.recordDenial(s, "rm -rf /var", "destructive")).toEqual({ consecutiveCount: 3, escalated: true });
  });

  it("a different denied command has its own count", () => {
    const { m } = manager(2);
    const s = sid();
    m.recordDenial(s, "rm -rf /var", "destructive");
    expect(m.recordDenial(s, "chmod 777 /etc", "permission change").consecutiveCount).toBe(1);
    expect(m.recordDenial(s, "rm -rf /var", "destructive")).toEqual({ consecutiveCount: 2, escalated: true });
  });

  it("an exploratory allow in between changes nothing", () => {
    const { m } = manager(3);
    const s = sid();
    m.recordDenial(s, "chmod 777 /etc", "permission change");
    m.recordAllow(s, "ls -la", { exploratory: true });
    m.recordAllow(s, "pwd", { exploratory: true });
    expect(m.recordDenial(s, "chmod 777 /etc", "permission change").consecutiveCount).toBe(2);
  });

  it("an unrelated substantive allow in between changes nothing either", () => {
    const { m } = manager(3);
    const s = sid();
    m.recordDenial(s, "./deploy/publish.sh", "unreviewed script");
    m.recordAllow(s, "gh issue create --title x --body y", { exploratory: false });
    expect(m.recordDenial(s, "./deploy/publish.sh", "unreviewed script").consecutiveCount).toBe(2);
  });

  it("an allowed run of the same command clears its count", () => {
    const { m } = manager(3);
    const s = sid();
    m.recordDenial(s, "cargo build --release", "denied");
    m.recordAllow(s, "cargo build --release", { exploratory: false });
    expect(m.recentDenial(s, "cargo build --release")).toBeUndefined();
    expect(m.recordDenial(s, "cargo build --release", "denied").consecutiveCount).toBe(1);
  });

  it("the window lapsing clears the count", () => {
    const { m, advance } = manager(2, 1000);
    const s = sid();
    m.recordDenial(s, "rm -rf /var", "destructive");
    advance(1001);
    expect(m.recentDenial(s, "rm -rf /var")).toBeUndefined();
    expect(m.recordDenial(s, "rm -rf /var", "destructive")).toEqual({ consecutiveCount: 1, escalated: false });
  });

  it("remembers the last denial reason for a retry inside the window", () => {
    const { m } = manager(3);
    const s = sid();
    m.recordDenial(s, "rm -rf /var", "destroys audit logs");
    expect(m.recentDenial(s, "sudo rm -rf /var 2>&1 | tail -5")?.reason).toBe("destroys audit logs");
  });
});

describe("StateManager.normalizeCommand", () => {
  const { m } = manager();
  it("ignores privilege prefixes, whitespace, fd redirections and trailing output shaping", () => {
    const key = m.normalizeCommand("cd /home/dev/web && ./deploy/publish.sh");
    expect(m.normalizeCommand("cd /home/dev/web  &&  ./deploy/publish.sh 2>&1 | tail -15")).toBe(key);
    expect(m.normalizeCommand("sudo rm -rf /var")).toBe(m.normalizeCommand("rm -rf /var"));
  });
  it("keeps genuinely different commands apart", () => {
    expect(m.normalizeCommand("rm -rf /var")).not.toBe(m.normalizeCommand("rm -rf /var/log"));
    expect(m.normalizeCommand("git status | tail -3")).toBe(m.normalizeCommand("git status"));
    expect(m.normalizeCommand("tail -3 /etc/passwd")).not.toBe(m.normalizeCommand("git status"));
  });
});

describe("heredoc bodies are part of a command's identity", () => {
  it("gives two different heredoc scripts different keys, and a retry of one the same key", () => {
    const { m } = manager();
    const a = "cd /srv/app && python3 - <<'PY'\nprint('a')\nPY";
    const b = "cd /srv/app && python3 - <<'PY'\nimport shutil; shutil.rmtree('/srv')\nPY";
    expect(m.normalizeCommand(a)).not.toBe(m.normalizeCommand(b));
    expect(m.normalizeCommand(a)).toBe(m.normalizeCommand(a));
  });
});
