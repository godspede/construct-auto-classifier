/**
 * Paths whose write/edit is judged by the model even when it resolves
 * inside the session's own workspace or a configured scratch root.
 *
 * The workspace fast-allow (`isWithinWorkspace`) assumes "inside the
 * session's own project directory" is evidence the write is ordinary
 * development work. That assumption breaks the moment the workspace IS (or
 * contains) somewhere a write has effect far outside this session: OpenCode
 * started with `cwd: "~"` makes `~/.bashrc` "inside the workspace" by the
 * letter of that check, and a shell rc file, a systemd unit, a git hook, or
 * a cron drop-in is dangerous specifically BECAUSE it runs later, unattended,
 * in a context that has nothing to do with the session that wrote it.
 *
 * This is deliberately a THIRD tier, distinct from both ends of the existing
 * ladder: not `isProtectedPath`/`isSecretPath`'s outright deny (a `.bashrc`
 * edit is routine far more often than not), and not the workspace/scratch
 * fast-allow (which is exactly the shortcut this exists to defeat) --
 * matching one of these patterns means "ask the model", nothing stronger and
 * nothing weaker. `~/.ssh/**` and `~/.gnupg/**` need no entry here: they
 * already deny outright via `isSecretPath`, a stricter outcome this tier
 * never overrides.
 */

const SENSITIVE_WRITE_PATTERNS: RegExp[] = [
  // bash/zsh/ksh shell startup files
  /(?:^|[\/\\])\.(?:bashrc|bash_profile|bash_login|bash_logout|profile|zshrc|zshenv|zprofile|zlogin|zlogout|kshrc)$/i,
  // fish shell config
  /(?:^|[\/\\])\.config[\/\\]fish[\/\\]config\.fish$/i,
  // PowerShell profiles: $PROFILE on Windows (Documents\(Windows)?PowerShell\...profile...ps1) and pwsh on Linux/macOS (~/.config/powershell/...)
  /(?:^|[\/\\])(?:Documents[\/\\](?:PowerShell|WindowsPowerShell)|\.config[\/\\]powershell)[\/\\][^\/\\]*profile[^\/\\]*\.ps1$/i,
  // git hooks (the scripts) and the setting that redirects which directory holds them
  /(?:^|[\/\\])\.git[\/\\]hooks(?:[\/\\]|$)/i,
  /(?:^|[\/\\])\.git[\/\\]config$/i,
  // anywhere under the system's etc -- /etc, macOS's /private/etc, Homebrew's
  // /usr/local/etc and /opt/homebrew/etc, Windows' System32\drivers\etc --
  // subsumes sudoers, cron.d/cron.daily/crontab, and systemd's own
  // system-wide unit directories, none of which need their own entry once the
  // whole tree is covered. Anchored to those locations: a project folder that
  // happens to be named etc is not one. A relative `etc/...` is judged where
  // it resolves, by the callers that know the directory. (/etc/shadow,
  // /etc/sudoers* etc. are additionally in SECRET_PATH/isSecretPath and deny
  // outright, stricter than this tier -- that check runs first and wins.)
  /^(?:\/private|\/usr\/local|\/opt\/homebrew)?\/etc(?:\/|$)/i,
  /(?:^|[\/\\])System32[\/\\]drivers[\/\\]etc(?:[\/\\]|$)/i,
  // per-user crontabs and systemd units, outside /etc
  /(?:^|[\/\\])var[\/\\]spool[\/\\]cron(?:[\/\\]|$)/i,
  /(?:^|[\/\\])\.config[\/\\]systemd[\/\\]user(?:[\/\\]|$)/i,
  // autostart / login items
  /(?:^|[\/\\])\.config[\/\\]autostart(?:[\/\\]|$)/i,
  /(?:^|[\/\\])Library[\/\\]LaunchAgents(?:[\/\\]|$)/i,
  /(?:^|[\/\\])Library[\/\\]LaunchDaemons(?:[\/\\]|$)/i,
  /(?:^|[\/\\])AppData[\/\\]Roaming[\/\\]Microsoft[\/\\]Windows[\/\\]Start Menu[\/\\]Programs[\/\\]Startup(?:[\/\\]|$)/i,
];

export function isSensitiveWriteTarget(rawPath: string): boolean {
  const normalized = rawPath.replace(/^~(?=[\/\\]|$)/, "/home/x");
  return SENSITIVE_WRITE_PATTERNS.some((re) => re.test(normalized));
}
