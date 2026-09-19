/**
 * Structural analysis of a shell command line, used to decide whether a
 * fast-allow rule is *entitled* to vouch for it.
 *
 * A fast-allow regex says "this verb is read-only". It cannot see that the same
 * line redirects stdout into /etc, passes `-i` to sed, hands `-delete` to find,
 * or hides a second command behind `$( )`. This module sees exactly those
 * things and nothing else: it does not judge intent, it reports the shapes that
 * make a read-only verb write, execute, or escape.
 */

export interface Segment {
  /** The simple command text, separators removed, quotes intact. */
  text: string;
  /** Whitespace-split words with surrounding quotes removed. */
  words: string[];
  /** Words after leading env assignments and privilege wrappers are dropped. */
  verb: string;
  /** Arguments after the verb. */
  args: string[];
  /** The command with env/privilege prefixes removed — what a rule is matched against. */
  stripped: string;
}

export interface CommandShape {
  segments: Segment[];
  /** `$( )`, backticks, `<( )`, `>( )` anywhere outside single quotes. */
  hasSubstitution: boolean;
  /** A here-document body follows the first line; only the first line was analysed. */
  hasHeredoc: boolean;
  /** Every reason the line may write, execute, or escape. Empty means provably none found. */
  tells: string[];
}

const PRIVILEGE_WRAPPERS = new Set(["sudo", "doas", "command", "builtin", "nohup", "time", "nice"]);
/** Env names whose assignment changes what an allowed verb actually runs. */
const HIJACK_ENV = /^(PATH|LD_[A-Z_]+|DYLD_[A-Z_]+|BASH_ENV|ENV|IFS|PS4|PROMPT_COMMAND|SHELLOPTS|GIT_(SSH|SSH_COMMAND|EXTERNAL_DIFF|PAGER|EDITOR|CONFIG[A-Z_]*|DIR|EXEC_PATH)|PAGER|EDITOR|VISUAL|PYTHONPATH|PYTHONSTARTUP|NODE_OPTIONS|PERL5OPT|RUBYOPT)$/;
const INTERPRETERS = new Set([
  "sh", "bash", "zsh", "dash", "ksh", "fish", "pwsh", "powershell", "cmd", "eval", "source", ".",
  "python", "python2", "python3", "perl", "ruby", "node", "bun", "deno", "php", "lua", "tclsh",
]);
const INLINE_CODE_FLAGS = new Set(["-c", "-e", "-E", "-command", "-encodedcommand", "-enc", "/c", "/k", "-r", "--eval", "--print", "-p"]);
/** Verbs that are small programming languages: their arguments can write files by themselves. */
const PROGRAMMABLE = new Set(["sed", "awk", "gawk", "mawk", "nawk", "perl", "jq"]);
const ALWAYS_WRITES_OR_EXECS = new Set([
  "tee", "xargs", "dd", "install", "rsync", "scp", "sftp", "ftp", "curl", "wget", "cp", "mv", "rm", "ln", "mkdir",
  "rmdir", "touch", "truncate", "chmod", "chown", "chgrp", "chattr", "setfacl", "shred", "mkfs", "mount", "umount",
  "kill", "pkill", "killall", "reboot", "shutdown", "systemctl", "service", "apt", "apt-get", "dnf", "yum", "pacman",
  "pip", "pip3", "npm", "npx", "pnpm", "yarn", "cargo", "make", "docker", "podman", "kubectl", "ssh", "exec", "env",
  "watch", "less", "more", "man", "vi", "vim", "nvim", "nano", "emacs", "crontab", "at", "git",
]);
/**
 * Paths whose mere reading is a credential exposure. A fast-allowed `cat` is
 * read-only, and reading these is exactly the read that must not be free.
 * Matched against every argument; the model judges anything that hits.
 */
const SECRET_PATH = new RegExp(
  [
    "\\/etc\\/(?:g?shadow|sudoers(?:\\.d)?(?:\\/|$)|ssh\\/ssh_host_[^\\s]*_key)",
    "(?:^|\\/)\\.(?:ssh|gnupg|aws|azure|kube|docker|password-store|netrc|pgpass|npmrc|pypirc|git-credentials|claude\\.json)(?:\\/|$)",
    "(?:^|\\/)\\.env(?:\\.[^\\s\\/]+)?$",
    "\\/proc\\/[^\\s\\/]+\\/(?:environ|cmdline)$",
    "\\.(?:pem|key|p12|pfx|keystore|jks|creds)$",
    "(?:^|\\/)(?:id_rsa|id_ed25519|id_ecdsa|id_dsa)(?:\\.pub)?$",
    "(?:^|\\/)[^\\/]*(?:secrets?|credentials?|tokens?|passwd|password)[^\\/]*\\.(?:json|ya?ml|toml|env|txt|ini|cfg)$",
    "(?:^|\\/)[^\\/]*(?:-tokens|-keys)[^\\/]*$",
    "(?:^|\\/)[^\\/]+\\.env$",
    // Harness/tool auth stores whose filename does not spell "secret",
    // "token", or "credential" but holds exactly that: a CLI's own config or
    // auth file under ~/.config is where it keeps its login.
    "(?:^|\\/)\\.config\\/[^\\/]+\\/(?:config|auth|hosts|credentials)\\.(?:toml|json|ya?ml)$",
    "(?:^|\\/)\\.claude\\/\\.credentials\\.json$",
  ].join("|"),
  "i"
);

/** Verbs in ALWAYS_WRITES_OR_EXECS that a rule may still name because their read-only subcommands are common. */
const VERBS_A_RULE_MAY_STILL_VOUCH_FOR = new Set(["git", "systemctl", "cargo", "npm", "docker", "kubectl", "make", "pip", "pip3"]);

export function analyzeCommand(command: string): CommandShape {
  const { segments: rawSegments, hasSubstitution, hasHeredoc } = splitSegments(command);
  const segments = rawSegments.map(parseSegment).filter((s) => s.words.length > 0);
  const tells: string[] = [];
  if (hasSubstitution) tells.push("command substitution");
  // The splitter stops at `<<`: whatever follows the here-document's body is
  // never parsed, so no rule can vouch for the line.
  if (hasHeredoc) tells.push("here-document (the rest of the line is not analyzed)");
  for (const seg of segments) {
    tells.push(...writeTells(seg));
  }
  return { segments, hasSubstitution, hasHeredoc, tells };
}

/**
 * Split a command line into simple commands on unquoted `;`, `|`, `||`, `&&`,
 * `&` and newlines. Everything after an unquoted `<<` (a here-document) on the
 * first line is dropped from analysis: it is data, and the redirect that
 * receives it is on the first line.
 */
export function splitSegments(command: string): { segments: string[]; hasSubstitution: boolean; hasHeredoc: boolean } {
  const segments: string[] = [];
  let cur = "";
  let quote: "'" | '"' | null = null;
  let hasSubstitution = false;
  let hasHeredoc = false;
  const push = () => {
    if (cur.trim()) segments.push(cur.trim());
    cur = "";
  };

  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    const next = command[i + 1];

    if (quote) {
      cur += ch;
      if (ch === "\\" && quote === '"') {
        cur += next ?? "";
        i++;
      } else if (ch === quote) {
        quote = null;
      } else if (quote === '"' && ch === "$" && next === "(") {
        hasSubstitution = true;
      } else if (quote === '"' && ch === "`") {
        hasSubstitution = true;
      }
      continue;
    }

    if (ch === "\\") {
      cur += ch + (next ?? "");
      i++;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      cur += ch;
      continue;
    }
    if (ch === "`" || ((ch === "$" || ch === "<" || ch === ">") && next === "(")) {
      hasSubstitution = true;
      cur += ch;
      continue;
    }
    if (ch === "<" && next === "<" && command[i + 2] !== "<") {
      // here-document: keep the first line for its redirect, drop the body
      hasHeredoc = true;
      const nl = command.indexOf("\n", i);
      cur += nl === -1 ? command.slice(i) : command.slice(i, nl);
      push();
      break;
    }
    if (ch === "\n" || ch === ";") {
      push();
      continue;
    }
    if (ch === "|") {
      push();
      if (next === "|") i++;
      continue;
    }
    if (ch === "&") {
      const prev = command[i - 1];
      if (next === "&") {
        push();
        i++;
        continue;
      }
      // `2>&1`, `>&2`, `&>` are redirections, not separators
      if (prev === ">" || prev === "<" || next === ">") {
        cur += ch;
        continue;
      }
      push();
      continue;
    }
    cur += ch;
  }
  push();
  return { segments, hasSubstitution, hasHeredoc };
}

/** Quote-aware word split; surrounding quotes are removed, contents kept verbatim. */
export function splitWords(segment: string): string[] {
  const words: string[] = [];
  let cur = "";
  let inWord = false;
  let quote: "'" | '"' | null = null;
  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i];
    if (quote) {
      if (ch === quote) {
        quote = null;
      } else if (ch === "\\" && quote === '"' && i + 1 < segment.length) {
        cur += segment[++i];
      } else {
        cur += ch;
      }
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      inWord = true;
      continue;
    }
    if (ch === "\\" && i + 1 < segment.length) {
      cur += segment[++i];
      inWord = true;
      continue;
    }
    if (/\s/.test(ch)) {
      if (inWord) words.push(cur);
      cur = "";
      inWord = false;
      continue;
    }
    cur += ch;
    inWord = true;
  }
  if (inWord) words.push(cur);
  return words;
}

function parseSegment(text: string): Segment {
  const words = splitWords(text);
  let i = 0;
  const dropped: string[] = [];
  // leading env assignments
  while (i < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i])) dropped.push(words[i++]);
  // privilege / wrapper verbs and their own flags
  while (i < words.length && PRIVILEGE_WRAPPERS.has(words[i])) {
    const wrapper = words[i++];
    if (wrapper === "sudo" || wrapper === "doas" || wrapper === "nice") {
      while (i < words.length && words[i].startsWith("-")) {
        const flag = words[i++];
        // flags that take a value: sudo -u USER, -g GROUP, doas -u USER, nice -n N
        if (/^-(u|g|n|C|D|h|p|r|t|T|U)$/.test(flag) && i < words.length) i++;
      }
    }
    while (i < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i])) dropped.push(words[i++]);
  }
  const verb = words[i] ?? "";
  const args = words.slice(i + 1);
  return { text, words, verb, args, stripped: [verb, ...args].join(" "), ...({ dropped } as {}) };
}

/** Leading `NAME=value` words before the verb -- the env assignments that
 * apply to this one simple command. Exported so a check that cares about a
 * specific variable (self-protection's `AUTO_CLASSIFIER_*` guard) does not
 * re-derive this from scratch. */
export function envAssignments(seg: Segment): string[] {
  return seg.words.filter((w) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(w) && seg.words.indexOf(w) < seg.words.indexOf(seg.verb));
}

/** Raw stdout/stderr redirect targets (fd duplication and /dev/null excluded,
 * neither is a write). Exported for the same reason as `envAssignments`: the
 * self-protection guard needs the actual target path, not just the tell
 * string `writeTells` reports for it. */
export function redirectTargets(seg: Segment): string[] {
  const targets: string[] = [];
  const redirect = /(?:^|\s)(?:\d*>>?|&>>?)\s*([^\s&|;]+)/g;
  let m: RegExpExecArray | null;
  while ((m = redirect.exec(seg.text)) !== null) {
    const target = m[1].replace(/^['"]|['"]$/g, "");
    if (target.startsWith("&")) continue; // 2>&1
    if (target === "/dev/null") continue;
    targets.push(target);
  }
  return targets;
}

/** Everything about one simple command that makes a read-only verb not read-only. */
function writeTells(seg: Segment): string[] {
  const tells: string[] = [];
  const verb = seg.verb.replace(/^.*\//, ""); // /usr/bin/tee -> tee

  for (const a of envAssignments(seg)) {
    const name = a.slice(0, a.indexOf("="));
    if (HIJACK_ENV.test(name)) tells.push(`${name}= prefix`);
  }

  for (const target of redirectTargets(seg)) tells.push(`redirect to ${target}`);

  if (INTERPRETERS.has(verb)) {
    if (seg.args.some((a) => INLINE_CODE_FLAGS.has(a.toLowerCase()))) tells.push(`${verb} runs inline code`);
    if (verb === "source" || verb === "." || verb === "eval") tells.push(`${verb} executes its argument`);
  }
  if (PROGRAMMABLE.has(verb)) tells.push(`${verb} is programmable`);
  if (ALWAYS_WRITES_OR_EXECS.has(verb) && !VERBS_A_RULE_MAY_STILL_VOUCH_FOR.has(verb)) tells.push(`${verb} writes or executes`);

  const has = (pred: (a: string) => boolean) => seg.args.some(pred);
  if (verb === "find" && has((a) => /^-(delete|exec|execdir|ok|okdir|fprint0?|fprintf|fls)$/.test(a))) tells.push("find with an action");
  if ((verb === "sort" || verb === "uniq") && has((a) => a === "-o" || a.startsWith("--output"))) tells.push(`${verb} -o`);
  if (verb === "uniq" && seg.args.filter((a) => !a.startsWith("-")).length >= 2) tells.push("uniq with an output operand");
  if (verb === "rg" && has((a) => a === "--pre" || a.startsWith("--pre="))) tells.push("rg --pre runs a preprocessor");
  if (verb === "git" && has((a) => a === "-c" || a.startsWith("--output") || a.startsWith("--exec-path") || a === "--git-dir")) tells.push("git with -c/--output/--exec-path/--git-dir");
  // Each of these runs a program: one named on the line (-O / --open-files-in-pager)
  // or one the repository's own config names (--ext-diff, --textconv).
  if (verb === "git" && has((a) => /^-O/.test(a) || a.startsWith("--open-files-in-pager") || a === "--ext-diff" || a === "--textconv")) tells.push("git runs a pager, diff driver or textconv program");
  if (has((a) => a.startsWith("--output") || a.startsWith("--out-file") || a.startsWith("--log-file"))) {
    if (verb !== "git") tells.push(`${verb} --output`);
  }
  if (verb === "tail" && has((a) => /^-[a-zA-Z]*f/.test(a) || a === "--follow")) tells.push("tail -f never returns");
  if (verb === "journalctl" && has((a) => /^--(?:vacuum-|rotate|flush|sync|relinquish|setup-keys)/.test(a))) tells.push("journalctl maintenance flag");
  if (verb === "journalctl" && has((a) => /^-[a-zA-Z]*f/.test(a) || a === "--follow")) tells.push("journalctl -f never returns");
  // PowerShell script blocks and expression evaluation run arbitrary code
  // inside an otherwise read-only cmdlet.
  if (seg.words.some((w) => /^(?:iex|invoke-expression|invoke-command|icm|start-process|saps)$/i.test(w))) tells.push("PowerShell evaluates code");
  if (/^[A-Za-z]+-[A-Za-z]+$/.test(verb) && /[{}]/.test(seg.text)) tells.push("PowerShell script block");
  // Raw tokens too: the shell-style word split consumes `\` as an escape, which
  // erases the separators of a Windows path (C:\Users\me\.ssh\id_rsa).
  const rawTokens = seg.text.split(/\s+/).slice(1).map((t) => t.replace(/^['"]|['"]$/g, ""));
  const secret = [...seg.args, ...rawTokens].find((a) => !a.startsWith("-") && SECRET_PATH.test(a.replace(/^~/, "/home/x").replace(/\\/g, "/")));
  if (secret) tells.push(`reads a secret-looking path (${secret})`);
  return tells;
}
