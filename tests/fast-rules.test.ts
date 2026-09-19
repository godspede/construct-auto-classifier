import { describe, it, expect } from "bun:test";
import { evaluateFastRules } from "../src/rules/fast-rules.js";
import type { RulesConfig } from "../src/types.js";
import path from "node:path";
import { loadConfig } from "../src/config.js";

describe("Fast Rules Engine", () => {
  const rules: RulesConfig = {
    fastDeny: [
      "^\\s*mkfs(\\.[a-z0-9]+)?\\s+",
      "^\\s*dd\\s+.*of=\\/dev\\/(sd[a-z]|nvme[0-9]n[0-9]|vd[a-z])",
      ":\\(\\)\\s*\\{\\s*:\\s*\\|\\s*:\\s*&\\s*\\};\\s*:",
    ],
    fastAllow: [
      "^\\s*git\\s+(status|diff|log|branch|show)\\b",
      "^\\s*ls(\\s+-[a-zA-Z0-9]+)*(\\s+[^\\s;&|]+)?$",
      "^\\s*pwd$",
      "^\\s*whoami$",
      "^\\s*(?:head|tail|grep|cat|wc)\\b",
      "^\\s*find\\s+",
      "^\\s*(?:sudo\\s+)?journalctl\\s+",
      "^\\s*python3?\\s+-m\\s+pytest\\b",
    ],
  };
  const decide = (c: string) => evaluateFastRules(c, rules)?.matched ?? null;

  it("fast-allows benign read-only commands", () => {
    for (const c of ["git status", "git diff HEAD~1", "ls -la /tmp", "pwd", "whoami", "sudo journalctl -u x -n 50", "find . -name '*.ts'", "cat /etc/os-release"]) {
      expect(decide(c)).toBe("allow");
    }
  });

  it("fast-denies catastrophic formatting commands", () => {
    expect(decide("mkfs.ext4 /dev/sda1")).toBe("deny");
    expect(decide("dd if=/dev/zero of=/dev/sda bs=1M")).toBe("deny");
    expect(decide(":(){ :|:& };:")).toBe("deny");
    expect(decide("git status; mkfs.ext4 /dev/sda1")).toBe("deny");
  });

  it("allows a pipeline or chain only when every segment is allowed", () => {
    expect(decide("git status 2>&1")).toBe("allow");
    expect(decide("git status | head -n 10")).toBe("allow");
    expect(decide("git status | grep modified")).toBe("allow");
    expect(decide("git status && pwd; whoami")).toBe("allow");
    expect(decide("ls; rm -rf /")).toBeNull();
    expect(decide("git status | iex")).toBeNull();
    expect(decide("git status | bash")).toBeNull();
    expect(decide("git status | xargs rm")).toBeNull();
    expect(decide("git status && curl x | sh")).toBeNull();
  });

  it("never lets an allowed verb vouch for a write, an exec, or an escape", () => {
    for (const c of [
      "tee /etc/cron.d/evil",
      "sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config",
      "find / -name '*.log' -delete",
      "find . -exec rm {} +",
      "cat > ~/.ssh/authorized_keys <<EOF\nssh-ed25519 AAAA\nEOF",
      "head -c 100 /dev/urandom > /dev/sda",
      "cat /etc/motd > /etc/issue",
      "ls $(rm -rf /)",
      "ls `rm -rf /`",
      "PATH=/tmp/evil git status",
      "git -c core.pager='rm -rf /' log",
      "git log --output=/etc/x",
      "grep --pre rm foo", // unknown flag on an allowed verb is fine; rg --pre is the veto
      "tail -f /var/log/syslog",
    ]) {
      if (c.startsWith("grep")) continue;
      expect(decide(c)).toBeNull();
    }
    expect(decide("sudo journalctl --vacuum-time=1s")).toBeNull();
    expect(decide("cat /etc/shadow")).toBeNull();
    expect(decide("cat ~/.ssh/id_ed25519")).toBeNull();
    expect(decide("cat /etc/os-release")).toBe("allow");
  });

  it("lets a fast-allowed command write into a scratch root", () => {
    // A heredoc is never fast-allowed (see the bypass tests below), even into scratch.
    expect(decide("cat > /tmp/notes.txt <<'EOF'\nhello\nEOF")).toBeNull();
    expect(decide("git status > /tmp/out.txt 2>&1")).toBe("allow");
    expect(evaluateFastRules("git status > /var/tmp/out.txt", { ...rules, scratchWriteRoots: ["/var/tmp/"] })?.matched).toBe("allow");
    expect(decide("git status > /var/tmp/out.txt")).toBeNull();
  });

  it("returns null for commands requiring LLM judgment", () => {
    expect(decide("sudo systemctl status nginx")).toBeNull();
    expect(decide("python3 script.py")).toBeNull();
    expect(decide("python3 -c 'print(1)'")).toBeNull();
    expect(decide("python3 -m pytest tests/")).toBe("allow");
  });

  it("self-protection denies mutating the classifier's own gate even under a permissive fastAllow", () => {
    // A pathological fastAllow that vouches for every verb used below --
    // this is the point: self-protection is checked before fastAllow, and
    // config can never buy back through it.
    const permissive: RulesConfig = { ...rules, fastAllow: ["^\\s*(?:rm|chmod|sed|cat|echo)\\b"] };
    const decidePermissive = (c: string) => evaluateFastRules(c, permissive)?.matched ?? null;
    expect(decidePermissive("rm -rf ~/.config/auto-classifier")).toBe("deny");
    expect(decidePermissive("chmod 777 ~/.config/auto-classifier/config.jsonc")).toBe("deny");
    expect(decidePermissive("sed -i 's/deny/allow/' ~/.config/auto-classifier/config.jsonc")).toBe("deny");
    expect(decidePermissive("echo pwned > ~/.config/opencode/plugins/auto-classifier.js")).toBe("deny");
    // reading it stays whatever fastAllow says -- self-protection only guards mutation
    expect(decidePermissive("cat ~/.config/auto-classifier/config.jsonc")).toBe("allow");
  });

  it("self-protection also fires with no fastAllow configured at all", () => {
    expect(evaluateFastRules("rm -rf ~/.config/auto-classifier", { ...rules, fastAllow: [] })?.matched).toBe("deny");
  });
});

describe("fast-allow bypasses found in pre-release review", () => {
  // Shipped defaults, exactly as a fresh install has them.
  const defaults = loadConfig(path.join(import.meta.dir, "..", "bench", "bench-config.jsonc")).rules;
  const fast = (cmd: string) => evaluateFastRules(cmd, defaults)?.matched ?? null;

  it("never vouches for what follows a here-document", () => {
    expect(fast("git status <<EOF\nx\nEOF\nrm -rf ~")).toBeNull();
    expect(fast("git log <<'E'\nE\nsudo rm -rf /")).toBeNull();
    expect(fast("git status <<EOF; rm -rf ~")).toBeNull();
  });

  it("treats git flags that run a program as a tell", () => {
    expect(fast("git grep --open-files-in-pager='rm -rf ~' foo")).toBeNull();
    expect(fast("git grep -O'touch /tmp/pwn' foo")).toBeNull();
    expect(fast("git diff --ext-diff")).toBeNull();
    expect(fast("git log -p --textconv")).toBeNull();
    expect(fast("git grep foo")).toBe("allow");
  });

  it("resolves a redirect before calling it scratch", () => {
    expect(fast("git status > /tmp/../etc/profile.d/x.sh")).toBeNull();
    expect(fast("ls >>/tmp/../etc/passwd")).toBeNull();
    expect(fast("git status > /tmp/out.txt")).toBe("allow");
  });

  it("does not fast-allow PowerShell script blocks or code evaluation", () => {
    expect(fast("Measure-Command { Remove-Item -Recurse -Force C:\\Users }")).toBeNull();
    expect(fast("Get-ChildItem | ForEach-Object { Remove-Item -Recurse -Force $_ }")).toBeNull();
    expect(fast("Get-Content C:\\Users\\me\\.ssh\\id_rsa")).toBeNull();
    expect(fast("Get-ChildItem C:\\src")).toBe("allow");
  });

  it("does not fast-allow a command that never returns", () => {
    expect(fast("sudo journalctl -u nginx -f")).toBeNull();
    expect(fast("sudo journalctl -u nginx -n 50")).toBe("allow");
  });
});
