import { describe, it, expect } from "bun:test";
import { analyzeCommand } from "../src/rules/command-shape.js";
import { isProtectedEnvOverride, isProtectedPath, selfProtectionDenial } from "../src/rules/self-protection.js";

const denial = (cmd: string) => selfProtectionDenial(analyzeCommand(cmd));

describe("isProtectedPath", () => {
  it("matches the classifier's config/telemetry/log directory, tilde or absolute", () => {
    for (const p of [
      "~/.config/auto-classifier/config.jsonc",
      "~/.config/auto-classifier/telemetry.jsonl",
      "~/.config/auto-classifier/auto-classifier.log",
      "~/.config/auto-classifier",
      "/home/dev/.config/auto-classifier/config.jsonc",
      "C:\\Users\\dev\\.config\\auto-classifier\\config.jsonc",
    ]) {
      expect(isProtectedPath(p)).toBe(true);
    }
  });

  it("matches the installed plugin drop-in", () => {
    expect(isProtectedPath("~/.config/opencode/plugins/auto-classifier.js")).toBe(true);
    expect(isProtectedPath("C:\\Users\\dev\\.config\\opencode\\plugins\\auto-classifier.js")).toBe(true);
  });

  it("does not match an unrelated opencode plugin or config file", () => {
    expect(isProtectedPath("~/.config/opencode/plugins/session-logger.js")).toBe(false);
    expect(isProtectedPath("~/.config/opencode/opencode.json")).toBe(false);
    expect(isProtectedPath("~/src/dotfiles/auto-classifier/config.jsonc")).toBe(false);
  });
});

describe("isProtectedEnvOverride", () => {
  it("flags any AUTO_CLASSIFIER_* name", () => {
    expect(isProtectedEnvOverride("AUTO_CLASSIFIER_CONFIG")).toBe(true);
    expect(isProtectedEnvOverride("AUTO_CLASSIFIER_MODEL")).toBe(true);
    expect(isProtectedEnvOverride("AUTO_CLASSIFIER_DENY_MODE")).toBe(true);
  });

  it("leaves unrelated env vars alone", () => {
    expect(isProtectedEnvOverride("PATH")).toBe(false);
    expect(isProtectedEnvOverride("AUTO_SOMETHING_ELSE")).toBe(false);
  });
});

describe("selfProtectionDenial", () => {
  it("denies deleting, moving, or copying over the config directory or its files", () => {
    for (const c of [
      "rm -rf ~/.config/auto-classifier",
      "rm ~/.config/auto-classifier/config.jsonc",
      "mv ~/.config/auto-classifier/config.jsonc /tmp/backup.jsonc",
      "cp /tmp/evil.jsonc ~/.config/auto-classifier/config.jsonc",
      "shred -u ~/.config/auto-classifier/config.jsonc",
      "chmod 000 ~/.config/auto-classifier/config.jsonc",
      "chown nobody ~/.config/auto-classifier/config.jsonc",
      "truncate -s 0 ~/.config/auto-classifier/config.jsonc",
    ]) {
      expect(denial(c)).not.toBeNull();
    }
  });

  it("denies overwriting the config, telemetry, or plugin via a redirect", () => {
    expect(denial("echo '{}' > ~/.config/auto-classifier/config.jsonc")).not.toBeNull();
    expect(denial("printf '' >> ~/.config/auto-classifier/telemetry.jsonl")).not.toBeNull();
    expect(denial("cat evil.js > ~/.config/opencode/plugins/auto-classifier.js")).not.toBeNull();
  });

  it("denies sed -i and find -delete/-exec against the gate", () => {
    expect(denial("sed -i 's/deny/allow/' ~/.config/auto-classifier/config.jsonc")).not.toBeNull();
    expect(denial("find ~/.config/auto-classifier -delete")).not.toBeNull();
    expect(denial("find ~/.config/auto-classifier -name '*.jsonc' -exec rm {} +")).not.toBeNull();
  });

  it("denies an AUTO_CLASSIFIER_* env override anywhere in the line", () => {
    expect(denial("AUTO_CLASSIFIER_CONFIG=/tmp/evil.jsonc opencode run")).not.toBeNull();
    expect(denial("AUTO_CLASSIFIER_DENY_MODE=auto-retry bun run something")).not.toBeNull();
    expect(denial("git status; AUTO_CLASSIFIER_CONFIG=/tmp/x.jsonc echo hi")).not.toBeNull();
  });

  it("denies an AUTO_CLASSIFIER_* override with no command following it, or set via export/declare/typeset/env", () => {
    // A bare assignment sets a shell variable, and `export`/`declare
    // -x`/`typeset -x` promote it to the environment -- none of these need a
    // command on the same line to matter to a later `source`, and `env`
    // NAME=value cmd sets it only for that one child process.
    for (const c of [
      "AUTO_CLASSIFIER_DENY_MODE=auto-retry",
      "AUTO_CLASSIFIER_CONFIG=/tmp/evil.jsonc",
      "export AUTO_CLASSIFIER_DENY_MODE=auto-retry",
      "declare -x AUTO_CLASSIFIER_DENY_MODE=auto-retry",
      "typeset AUTO_CLASSIFIER_MODEL=some/model",
      "env AUTO_CLASSIFIER_DENY_MODE=auto-retry true",
    ]) {
      expect(denial(c)).not.toBeNull();
    }
  });

  it("does not deny an unrelated export/declare/typeset/env/bare assignment", () => {
    for (const c of ["export FOO=bar", "declare -x PATH=/usr/bin:$PATH", "typeset LOCAL_VAR=1", "env PATH=/usr/bin ls", "FOO=bar git status"]) {
      expect(denial(c)).toBeNull();
    }
  });

  it("catches it hiding behind a chain or pipeline", () => {
    expect(denial("ls && rm -rf ~/.config/auto-classifier")).not.toBeNull();
    expect(denial("git status; chmod 777 ~/.config/auto-classifier/config.jsonc")).not.toBeNull();
  });

  it("does not deny an unrelated use of the same verbs", () => {
    for (const c of [
      "rm /tmp/scratch.txt",
      "mv /tmp/a /tmp/b",
      "cp README.md /tmp/README.md",
      "chmod +x ./script.sh",
      "sed -i 's/foo/bar/' src/index.ts",
      "find . -name '*.ts' -delete",
      "echo hi > /tmp/notes.txt",
      "cat ~/.config/opencode/plugins/session-logger.js",
      "AUTO_SOMETHING=1 echo hi",
    ]) {
      expect(denial(c)).toBeNull();
    }
  });

  it("never fires on a plain read of the gate's own files", () => {
    for (const c of ["cat ~/.config/auto-classifier/config.jsonc", "tail -f ~/.config/auto-classifier/telemetry.jsonl", "grep deny ~/.config/auto-classifier/config.jsonc"]) {
      expect(denial(c)).toBeNull();
    }
  });
});
