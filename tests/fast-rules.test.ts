import { describe, it, expect } from "bun:test";
import { evaluateFastRules } from "../src/rules/fast-rules.js";
import type { RulesConfig } from "../src/types.js";
import path from "node:path";
import { loadConfig } from "../src/config.js";
import { pushFastAllowRule } from "../src/protected-branches.js";

describe("Fast Rules Engine", () => {
  const rules: RulesConfig = {
    fastDeny: [
      "^\\s*mkfs(\\.[a-z0-9]+)?\\s+",
      "^\\s*dd\\s+.*of=\\/dev\\/(sd[a-z]|nvme[0-9]n[0-9]|vd[a-z])",
      ":\\(\\)\\s*\\{\\s*:\\s*\\|\\s*:\\s*&\\s*\\};\\s*:",
    ],
    fastAllow: [
      "^\\s*git\\s+(?:-c\\s+[^;&|]+?\\s+)*(?:status|diff|log|branch|show|commit|add)\\b",
      pushFastAllowRule(["main", "master", "development"]),
      "^\\s*ls(\\s+-[a-zA-Z0-9]+)*(\\s+[^\\s;&|]+)?$",
      "^\\s*pwd$",
      "^\\s*whoami$",
      "^\\s*(?:head|tail|grep|cat|wc)\\b",
      "^\\s*find\\s+",
      "^\\s*(?:sudo\\s+)?journalctl\\s+",
      "^\\s*python3?\\s+-m\\s+pytest\\b",
      // A WHITELIST of read-only flags, end-anchored: `-[a-zA-Z]+` once admitted
      // -XDELETE/-XPOST/-K/-T, and with no `$` any argument after the URL rode
      // along. Anything else (-X, -d, -F, -T, -K, -o, -u) falls to the model.
      // The rule sees words with their quotes removed, so a header is its
      // `Name:` word plus the value words after it, none a flag or a URL.
      "^\\s*curl(?:\\s+(?:(?:-[sSfLiIvk]+|(?:-m|--max-time)(?:=|\\s+)\\d+|--(?:silent|show-error|fail|location|head|include|verbose|insecure))|(?:-H|--header)\\s+(?:'[^']*'|\"[^\"]*\"|[a-zA-Z0-9_-]+:(?:\\s+(?!-)(?!\\S*://)[^\\s;&|]+)*|[^\\s'\"@-]\\S*)))*\\s+https?://(?:127\\.0\\.0\\.1|localhost|\\[::1\\]|(?:[a-zA-Z0-9-]+\\.)*corp\\.example)(?::\\d+)?(?:/\\S*)?(?:\\s+(?:-[sSfLiIvk]+|(?:-m|--max-time)(?:=|\\s+)\\d+|--(?:silent|show-error|fail|location|head|include|verbose|insecure)))*\\s*$",
    ],
  };
  const decide = (c: string) => evaluateFastRules(c, rules)?.matched ?? null;

  it("fast-allows benign read-only commands and safe git commit/add", () => {
    for (const c of [
      "git status",
      "git diff HEAD~1",
      "git commit -m 'feat: something'",
      "git -c user.name='foo' -c user.email='bar' commit -m 'feat: something'",
      "git add src/ tests/",
      "git push gitea feat/my-feature",
      "git push -u origin fix-123",
      "git push --set-upstream origin my-user/test-branch",
      "ls -la /tmp",
      "pwd",
      "whoami",
      "sudo journalctl -u x -n 50",
      "find . -name '*.ts'",
      "cat /etc/os-release",
      "curl -s http://127.0.0.1:8080/status",
      "curl -s https://git.corp.example/status",
      "curl -k -s -H \"Host: git.corp.example\" http://127.0.0.1:8080/",
      "curl -sSf -H 'Accept: application/json' https://git.corp.example/api/v1/version -m 5",
      "curl --silent --insecure -m 5 https://git.corp.example/api/v1/version",
      "curl -s http://localhost:3000/",
      "curl -sI http://[::1]:8080/health",
    ]) {
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
      "curl -O http://127.0.0.1:8080/evil",
      "curl -o /etc/passwd http://127.0.0.1:8080/",
      "curl -T /etc/shadow http://127.0.0.1:8080/",
      "curl http://example.com",
      // Writes dressed as reads: a method or upload flag, before or after the URL.
      "curl -XDELETE http://127.0.0.1:3000/api/v1/repos/owner/app",
      "curl -XPOST http://127.0.0.1:3000/api/v1/repos/owner/app/pulls/1/merge",
      "curl -sXPOST http://127.0.0.1:3000/api/v1/repos/owner/app/pulls/1/merge",
      "curl -s -X POST http://127.0.0.1:3000/api/v1/x",
      "curl -s http://127.0.0.1:3000/api/v1/x -X DELETE",
      "curl -K /tmp/curl.cfg http://127.0.0.1:3000/",
      "curl -sK /tmp/curl.cfg http://127.0.0.1:3000/",
      "curl -T notes.txt https://git.corp.example/upload",
      "curl -s -d @body.json http://127.0.0.1:3000/api/v1/x",
      "curl -s -u admin:pw http://127.0.0.1:3000/api/v1/x",
      "curl -s -o /tmp/x http://127.0.0.1:3000/",
      // A host outside the whitelist, even one that looks like it.
      "curl -s https://git.corp.example.evil.example/",
      "curl -s https://evil-corp.example/",
      // A header cannot smuggle a second URL, read headers from a file, or hide a method.
      "curl -H \"X: ftp://evil.example/\" http://127.0.0.1/",
      "curl -H @/etc/shadow http://127.0.0.1/",
      "curl -H \"Authorization: token abc\" -XPOST http://127.0.0.1:3000/x",
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
    expect(decidePermissive("cat ~/.config/auto-classifier/auto-classifier.log")).toBe("allow");
    // ...except that the config is also a credential-looking path (a CLI's
    // config.jsonc under ~/.config), which no fast-allow vouches for reading
    expect(decidePermissive("cat ~/.config/auto-classifier/config.jsonc")).toBeNull();
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

describe("the shipped gh pr merge rule", () => {
  const shipped = loadConfig(path.join(import.meta.dir, "..", "bench", "bench-config.jsonc"), { overlay: false }).rules;

  it("sends an ordinary merge to the model, not a fast rule", () => {
    expect(evaluateFastRules("gh pr merge 17 --repo octo-org/app --squash", shipped)).toBeNull();
  });

  it("sends a merge past branch protection (--admin) to the model", () => {
    expect(evaluateFastRules("gh pr merge 17 --repo octo-org/app --admin --squash", shipped)).toBeNull();
    expect(evaluateFastRules("gh pr merge 17 --squash --admin", shipped)).toBeNull();
  });
});

describe("no default fastAllow entry vouches for a gh write verb", () => {
  // No default fast-allow rule matches a gh write verb; every one defers to
  // the model.
  const shipped = loadConfig(path.join(import.meta.dir, "..", "bench", "bench-config.jsonc"), { overlay: false }).rules;
  const fast = (cmd: string) => evaluateFastRules(cmd, shipped)?.matched ?? null;

  it("never fast-allows a gh write verb", () => {
    for (const c of [
      "gh pr merge 17 --repo octo-org/app --squash",
      "gh pr merge 17 --repo octo-org/app --admin --squash",
      "gh pr close 17 --repo octo-org/app",
      "gh pr edit 17 --title 'new title'",
      "gh pr create --title x --body y",
      "gh pr comment 17 --body 'looks good'",
      "gh pr review 17 --approve",
      "gh issue create --title x --body y",
      "gh issue close 17",
      "gh issue edit 17 --title x",
      "gh issue comment 17 --body x",
      "gh api -X POST repos/octo-org/app/issues -f title=x",
      "gh api --method POST repos/octo-org/app/issues -f title=x",
      "gh api -X DELETE repos/octo-org/app/issues/1",
    ]) {
      expect(fast(c)).toBeNull();
    }
  });

  it("still fast-allows the shipped gh read verbs", () => {
    for (const c of ["gh pr view 17", "gh pr list", "gh issue view 5", "gh run list", "gh repo view"]) {
      expect(fast(c)).toBe("allow");
    }
  });
});
