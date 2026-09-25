import { describe, it, expect } from "bun:test";
import { isSensitiveWriteTarget } from "../src/rules/sensitive-write.js";

describe("isSensitiveWriteTarget", () => {
  it("flags shell startup files, tilde or absolute", () => {
    for (const p of ["~/.bashrc", "~/.zshrc", "~/.profile", "~/.bash_profile", "/home/dev/.bashrc"]) {
      expect(isSensitiveWriteTarget(p)).toBe(true);
    }
  });

  it("flags PowerShell profile paths", () => {
    for (const p of [
      "C:\\Users\\dev\\Documents\\PowerShell\\Microsoft.PowerShell_profile.ps1",
      "C:\\Users\\dev\\Documents\\WindowsPowerShell\\profile.ps1",
      "~/.config/powershell/Microsoft.PowerShell_profile.ps1",
    ]) {
      expect(isSensitiveWriteTarget(p)).toBe(true);
    }
  });

  it("flags git hooks and .git/config (core.hooksPath lives there)", () => {
    expect(isSensitiveWriteTarget("~/repo/.git/hooks/pre-commit")).toBe(true);
    expect(isSensitiveWriteTarget("~/repo/.git/config")).toBe(true);
  });

  it("flags anywhere under /etc, crontabs, and systemd user units", () => {
    for (const p of ["/etc/cron.d/x", "/etc/sudoers.d/x", "/etc/systemd/system/x.service", "/var/spool/cron/crontabs/dev", "~/.config/systemd/user/x.service"]) {
      expect(isSensitiveWriteTarget(p)).toBe(true);
    }
  });

  it("flags autostart / login item locations", () => {
    for (const p of [
      "~/.config/autostart/x.desktop",
      "~/Library/LaunchAgents/com.x.plist",
      "~/Library/LaunchDaemons/com.x.plist",
      "C:\\Users\\dev\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.lnk",
    ]) {
      expect(isSensitiveWriteTarget(p)).toBe(true);
    }
  });

  it("leaves an ordinary workspace file alone", () => {
    for (const p of ["/work/src/x.ts", "~/repo/README.md", "/tmp/scratch.txt"]) {
      expect(isSensitiveWriteTarget(p)).toBe(false);
    }
  });
});
