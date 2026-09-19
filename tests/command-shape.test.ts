import { describe, it, expect } from "bun:test";
import { analyzeCommand, envAssignments, redirectTargets, splitSegments, splitWords } from "../src/rules/command-shape.js";

describe("splitSegments", () => {
  it("splits on every unquoted separator and keeps quoted ones", () => {
    const { segments } = splitSegments(`git status; ls -la && pwd || whoami | head -3\necho 'a;b|c'`);
    expect(segments).toEqual(["git status", "ls -la", "pwd", "whoami", "head -3", "echo 'a;b|c'"]);
  });

  it("does not split on fd redirections", () => {
    expect(splitSegments("git status 2>&1").segments).toEqual(["git status 2>&1"]);
    expect(splitSegments("cmd &>/dev/null").segments).toEqual(["cmd &>/dev/null"]);
    expect(splitSegments("cmd >&2").segments).toEqual(["cmd >&2"]);
  });

  it("flags command substitution in every spelling", () => {
    expect(splitSegments("ls $(rm -rf /)").hasSubstitution).toBe(true);
    expect(splitSegments("ls `rm -rf /`").hasSubstitution).toBe(true);
    expect(splitSegments("diff <(a) <(b)").hasSubstitution).toBe(true);
    expect(splitSegments(`echo "$(whoami)"`).hasSubstitution).toBe(true);
    expect(splitSegments("echo '$(not run)'").hasSubstitution).toBe(false);
  });

  it("keeps a here-document's first line and drops its body", () => {
    const r = splitSegments("cat > /tmp/x <<'EOF'\nrm -rf /\nEOF");
    expect(r.hasHeredoc).toBe(true);
    expect(r.segments).toEqual(["cat > /tmp/x <<'EOF'"]);
  });
});

describe("splitWords", () => {
  it("removes quotes and honours escapes", () => {
    expect(splitWords(`sed -i 's/a b/c/' "my file.txt" back\\ slash`)).toEqual(["sed", "-i", "s/a b/c/", "my file.txt", "back slash"]);
  });
});

describe("analyzeCommand tells", () => {
  const tells = (cmd: string) => analyzeCommand(cmd).tells;

  it("finds nothing on plain reads", () => {
    for (const c of ["git status", "ls -la /etc", "sudo -u root cat /etc/os-release", "grep -rn foo src/ | head", "pytest tests/ 2>&1", "cmd >/dev/null 2>&1"]) {
      expect(tells(c)).toEqual([]);
    }
  });

  it("strips privilege and env prefixes to find the verb", () => {
    const seg = analyzeCommand("FOO=1 sudo -u root -E git status").segments[0];
    expect(seg.verb).toBe("git");
    expect(seg.stripped).toBe("git status");
  });

  it("reports file redirects but not scratch decisions (that is the rule engine's call)", () => {
    expect(tells("cat > /etc/cron.d/x")).toContain("redirect to /etc/cron.d/x");
    expect(tells("head -c 100 /dev/urandom > /dev/sda")).toContain("redirect to /dev/sda");
    expect(tells("cat > /tmp/x <<'EOF'\nbody\nEOF")).toEqual(["here-document (the rest of the line is not analyzed)", "redirect to /tmp/x"]);
  });

  it("reports the write-capable verbs and flags", () => {
    expect(tells("tee /etc/cron.d/evil")).toContain("tee writes or executes");
    expect(tells("sed -i 's/a/b/' /etc/ssh/sshd_config")).toContain("sed is programmable");
    expect(tells("awk '{print > \"/etc/x\"}' f")).toContain("awk is programmable");
    expect(tells("find / -name '*.log' -delete")).toContain("find with an action");
    expect(tells("find . -exec rm {} +")).toContain("find with an action");
    expect(tells("sort -o /etc/passwd x")).toContain("sort -o");
    expect(tells("rg --pre rm foo")).toContain("rg --pre runs a preprocessor");
    expect(tells("git -c core.pager='rm -rf /' log")).toContain("git with -c/--output/--exec-path/--git-dir");
    expect(tells("git log --output=/etc/x")).toContain("git with -c/--output/--exec-path/--git-dir");
    expect(tells("ls | xargs rm")).toContain("xargs writes or executes");
    expect(tells("tail -f /var/log/syslog")).toContain("tail -f never returns");
  });

  it("reports a secret-looking path in any argument, and only those", () => {
    const procEnv = ["", "proc", "1234", "environ"].join("/");
    for (const c of [
      "cat /etc/shadow",
      "sudo cat /etc/sudoers",
      "cat ~/.ssh/id_ed25519",
      "head -c 100 /home/dev/.ssh/authorized_keys",
      "cat .env",
      "cat /home/dev/app/.env.production",
      "grep -r TOKEN /etc/app/secrets.env",
      "cat /etc/app/api-tokens.toml",
      "cat ~/.aws/credentials",
      `cat ${procEnv}`,
      "cat server.pem",
      "cat secrets.yaml",
      "ls ~/.gnupg/",
      "cat /var/lib/nats/app.creds",
      "cat ~/.config/opencode/auth.json",
      "cat ~/.config/some-cli/config.toml",
      "cat ~/.config/gh/hosts.yml",
      "cat ~/.claude/.credentials.json",
    ]) {
      expect(tells(c).some((t) => t.startsWith("reads a secret-looking path"))).toBe(true);
    }
    for (const c of ["cat /etc/os-release", "cat README.md", "cat src/environment.ts", "git log --oneline", "cat /etc/passwd", "ls -la ~/.config/opencode/", "cat package.json", "cat tokenizer.ts"]) {
      expect(tells(c).some((t) => t.startsWith("reads a secret-looking path"))).toBe(false);
    }
  });

  it("reports journalctl maintenance flags", () => {
    expect(tells("sudo journalctl --vacuum-time=1s")).toContain("journalctl maintenance flag");
    expect(tells("sudo journalctl -u nginx -n 50")).toEqual([]);
  });

  it("reports interpreters given inline code, but not a module run", () => {
    expect(tells("python3 -c 'import os; os.remove(\"x\")'")).toContain("python3 runs inline code");
    expect(tells("bash -c 'rm -rf /'")).toContain("bash runs inline code");
    expect(tells("pwsh -Command Remove-Item x")).toContain("pwsh runs inline code");
    expect(tells("python3 -m pytest")).toEqual([]);
  });

  it("reports env prefixes that change what the verb runs", () => {
    expect(tells("PATH=/tmp/evil:$PATH git status")).toContain("PATH= prefix");
    expect(tells("LD_PRELOAD=/tmp/x.so ls")).toContain("LD_PRELOAD= prefix");
    expect(tells("GIT_PAGER='rm -rf /' git log")).toContain("GIT_PAGER= prefix");
    expect(tells("RUST_LOG=debug cargo check")).toEqual([]);
  });
});

describe("envAssignments and redirectTargets (exported for self-protection.ts)", () => {
  it("returns only the leading assignments, in order", () => {
    const seg = analyzeCommand("FOO=1 BAR=2 sudo git status").segments[0];
    expect(envAssignments(seg)).toEqual(["FOO=1", "BAR=2"]);
    expect(envAssignments(analyzeCommand("git status").segments[0])).toEqual([]);
  });

  it("returns raw redirect targets, excluding fd dups and /dev/null", () => {
    const seg = analyzeCommand("cat x > /tmp/out.txt 2>&1").segments[0];
    expect(redirectTargets(seg)).toEqual(["/tmp/out.txt"]);
    expect(redirectTargets(analyzeCommand("cmd >/dev/null 2>&1").segments[0])).toEqual([]);
    expect(redirectTargets(analyzeCommand("cmd >> /tmp/a.log").segments[0])).toEqual(["/tmp/a.log"]);
  });
});
