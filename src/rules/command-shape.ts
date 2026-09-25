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
  /** Every redirect on the line, segment by segment (`scanRedirects`). */
  redirects: Redirect[];
  /**
   * Every construct on the line the analyser does not fully model
   * (`unmodelledConstructs`). Non-empty means the line is never allowed
   * without the model. Each is also a tell.
   */
  unmodelled: string[];
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

/** The tell a here-document carries: the splitter stops at `<<`, so nothing after it is parsed. */
const HEREDOC_TELL = "here-document (its body and anything after it is not analysed)";

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
 *
 * Exported so a file-tool guard (OpenCode's `read`/`write`/`edit`, which
 * receive a target path directly, with no shell command to parse) can deny
 * against the identical list rather than forking it -- see
 * `src/rules/self-protection.ts` for the same reasoning applied to
 * `isProtectedPath`.
 */
export const SECRET_PATH = new RegExp(
  [
    "\\/etc\\/(?:g?shadow|sudoers(?:\\.d)?(?:\\/|$)|ssh\\/ssh_host_[^\\s]*_key)",
    "(?:^|\\/)\\.(?:ssh|gnupg|aws|azure|kube|docker|password-store|netrc|pgpass|npmrc|pypirc|git-credentials|claude\\.json)(?:\\/|$)",
    "(?:^|\\/)\\.env(?:\\.[^\\s\\/]+)?$",
    "\\/proc\\/[^\\s\\/]+\\/(?:environ|cmdline)$",
    "\\.(?:pem|key|p12|pfx|keystore|jks|creds)$",
    "(?:^|\\/)(?:id_rsa|id_ed25519|id_ecdsa|id_dsa)(?:\\.pub)?$",
    "(?:^|\\/)[^\\/]*(?:secrets?|credentials?|tokens?|passwd|password)[^\\/]*\\.(?:jsonc?|ya?ml|toml|env|txt|ini|cfg)$",
    "(?:^|\\/)[^\\/]*(?:-tokens|-keys)[^\\/]*$",
    "(?:^|\\/)[^\\/]+\\.env$",
    // Harness/tool auth stores whose filename does not spell "secret",
    // "token", or "credential" but holds exactly that: a CLI's own config or
    // auth file under ~/.config is where it keeps its login.
    "(?:^|\\/)\\.config\\/[^\\/]+\\/(?:config|auth|hosts|credentials)\\.(?:toml|jsonc?|ya?ml)$",
    "(?:^|\\/)\\.claude\\/\\.credentials\\.json$",
  ].join("|"),
  "i"
);

/** Verbs in ALWAYS_WRITES_OR_EXECS that a rule may still name because their read-only subcommands are common. */
const VERBS_A_RULE_MAY_STILL_VOUCH_FOR = new Set(["git", "systemctl", "cargo", "npm", "docker", "kubectl", "make", "pip", "pip3", "curl"]);

export function analyzeCommand(command: string): CommandShape {
  const { segments: rawSegments, hasSubstitution, hasHeredoc } = splitSegments(command);
  const segments = rawSegments.map(parseSegment).filter((s) => s.words.length > 0);
  const tells: string[] = [];
  const redirects: Redirect[] = [];
  const unmodelled = unmodelledConstructs(command);
  tells.push(...unmodelled);
  if (hasSubstitution) tells.push("command substitution");
  // The splitter stops at `<<`: whatever follows the here-document's body is
  // never parsed, so no rule can vouch for the line.
  if (hasHeredoc && !tells.includes(HEREDOC_TELL)) tells.push(HEREDOC_TELL);
  for (const seg of segments) {
    const own = scanRedirects(seg.text);
    redirects.push(...own);
    for (const r of own) if (redirectWrites(r) && !tells.includes(redirectTell(r))) tells.push(redirectTell(r));
    // A here-string feeds stdin, so it always carries its own tell and no
    // fast-allow rule vouches for the line.
    if (own.some((r) => r.kind === "herestring") && !tells.includes("here-string")) tells.push("here-string");
    for (const t of writeTells(seg)) if (!tells.includes(t)) tells.push(t);
    // A wrapper (`timeout 5 sed -i …`, `env tee …`) hides nothing: the command
    // it runs carries its own tells. This only ever adds tells, so it can only
    // take a fast-allow away, never grant one.
    for (const t of writeTells(unwrapSegment(seg))) if (!tells.includes(t)) tells.push(t);
  }
  return { segments, hasSubstitution, hasHeredoc, tells, redirects, unmodelled };
}

/**
 * Split a command line into simple commands on unquoted `;`, `|`, `||`, `&&`,
 * `&` and newlines. Everything after an unquoted `<<` (a here-document) on the
 * first line is dropped from analysis: it is data, and the redirect that
 * receives it is on the first line.
 *
 * A comment is dropped as bash drops it: an unquoted, unescaped `#` at the
 * start of a word runs to the end of its line, and a quote character inside
 * it is not a quote. A `#` inside a word (`a#b`, `$#`, `'x'#y`), inside quotes
 * or escaped is an ordinary character. Any line with a `#` outside quotes is
 * still never allowed without the model (`unmodelledConstructs`), because not
 * every shell draws the word boundary where bash does.
 */
export function splitSegments(command: string): { segments: string[]; hasSubstitution: boolean; hasHeredoc: boolean } {
  const segments: string[] = [];
  let cur = "";
  // `ansi` is bash's `$'…'`, inside which a backslash escapes the next
  // character, a quote included: `$'a\''` ends at the last quote, not the first.
  let quote: "'" | '"' | "ansi" | null = null;
  let hasSubstitution = false;
  let hasHeredoc = false;
  // The last character appended was an unquoted, unescaped `>` or `<`, so a
  // `&` or `|` right after it belongs to a redirect operator (`2>&1`, `<&3`,
  // `>|`). An escaped `\>` is a literal argument: the `&` after it is a
  // separator, and the words after it are another command.
  let lastOp: ">" | "<" | null = null;
  // The next character starts a word: nothing but blanks and operators since
  // the start of the line or the last word. Only there does `#` open a comment.
  let wordStart = true;
  const push = () => {
    if (cur.trim()) segments.push(cur.trim());
    cur = "";
    lastOp = null;
    wordStart = true;
  };

  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    const next = command[i + 1];
    const afterOp = lastOp;
    lastOp = null;

    if (quote) {
      wordStart = false;
      cur += ch;
      if (ch === "\\" && (quote === '"' || quote === "ansi")) {
        cur += next ?? "";
        i++;
      } else if (ch === (quote === "ansi" ? "'" : quote)) {
        quote = null;
      } else if (quote === '"' && ch === "$" && next === "(") {
        hasSubstitution = true;
      } else if (quote === '"' && ch === "`") {
        hasSubstitution = true;
      }
      continue;
    }

    if (ch === "#" && wordStart) {
      // A comment: skip to the end of the line, and let the newline split.
      const nl = command.indexOf("\n", i);
      i = (nl === -1 ? command.length : nl) - 1;
      continue;
    }
    if (ch === "\\") {
      // A backslash-newline is removed before words are formed, so it leaves
      // the word boundary where it was; any other escaped character is a word.
      if (next !== "\n") wordStart = false;
      cur += ch + (next ?? "");
      i++;
      continue;
    }
    if (ch === "$" && next === "'") {
      quote = "ansi";
      wordStart = false;
      cur += "$'";
      i++;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      wordStart = false;
      cur += ch;
      continue;
    }
    if (ch === "<" && next === "<" && command[i + 2] === "<") {
      // `<<<` is a here-string: its word is on this line, and the next line is
      // another command, not a here-document body.
      cur += "<<<";
      i += 2;
      wordStart = true;
      continue;
    }
    if (ch === "`" || ((ch === "$" || ch === "<" || ch === ">") && next === "(")) {
      hasSubstitution = true;
      // The `(` that follows is appended next and starts a word; a backtick's
      // body is read by bash as a whole before it is parsed, so a `#` right
      // after one is not a comment on this line.
      wordStart = false;
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
      // `>|` is a redirect (clobber), not a pipe
      if (afterOp === ">") {
        cur += ch;
        wordStart = true;
        continue;
      }
      push();
      if (next === "|") i++;
      continue;
    }
    if (ch === "&") {
      if (next === "&") {
        push();
        i++;
        continue;
      }
      // `2>&1`, `>&2`, `<&3`, `&>` are redirections, not separators
      if (afterOp !== null || next === ">") {
        cur += ch;
        wordStart = true;
        continue;
      }
      push();
      continue;
    }
    cur += ch;
    if (ch === ">" || ch === "<") lastOp = ch;
    // Blanks and bash's other metacharacters end a word.
    wordStart = ch === " " || ch === "\t" || ch === ">" || ch === "<" || ch === "(" || ch === ")";
  }
  push();
  return { segments, hasSubstitution, hasHeredoc };
}

/** A line longer than this is never allowed without the model. */
export const MAX_ANALYSED_LENGTH = 8192;

/**
 * Words that, in command position, are shell syntax the splitter does not
 * model (a compound command, a definition, a negation) or that change how the
 * rest of the line is read or what a later verb runs.
 */
const UNMODELLED_COMMAND_WORDS = new Map<string, string>(Object.entries({
  "if": "compound command", "then": "compound command", "elif": "compound command", "else": "compound command",
  "fi": "compound command", "for": "compound command", "while": "compound command", "until": "compound command",
  "do": "compound command", "done": "compound command", "case": "compound command", "esac": "compound command",
  "select": "compound command", "[[": "compound command", "]]": "compound command", "{": "brace group", "}": "brace group",
  "!": "negated pipeline", "function": "function definition", "coproc": "coprocess",
  "alias": "alias", "unalias": "alias",
  "shopt": "shell option change", "set": "shell option change", "hash": "command lookup change",
  "enable": "builtin change", "trap": "trap",
}));

/** Words after which the next word is still in command position. */
const COMMAND_POSITION_PREFIXES = new Set(["!", "{", "if", "then", "elif", "else", "while", "until", "do", "time", "builtin", "command", "coproc"]);

/** Characters that are an escape to bash but a path character, a separator or a quote to PowerShell or cmd. */
const CROSS_SHELL_ESCAPED = new Set([";", "&", "|", "<", ">", "(", ")", "{", "}", "'", '"', "`", "\n"]);

/**
 * Every construct on a command line that the analyser does not fully model,
 * as short reasons; empty when there is none. A line with any of them is never
 * allowed without the model -- no fast allow, no landed-script trust, no
 * scratch exemption, no cache hit -- and still meets every deterministic
 * denial on the way there. This is a backstop: it does not rely on the
 * splitter being right, so it reads the raw text with its own quote tracking
 * and errs towards flagging.
 *
 * What it flags, and why each one is not modelled:
 * - a `#` outside quotes (a comment; not every shell draws the word boundary
 *   where bash does) and PowerShell's `<# ... #>`, anywhere;
 * - grouping and substitution: any unquoted `(` or `)` (a subshell, `$( )`,
 *   `$(( ))`, `<( )`/`>( )`, a `name()` definition, an extended glob, an
 *   array), backticks, and a `{` or `}` standing as a word;
 * - reserved words and state-changing builtins in command position
 *   (`UNMODELLED_COMMAND_WORDS`), and `time` given options;
 * - quoting the tracker cannot follow: `$"..."`, quotes or expansions nested
 *   in `${...}`, an unterminated quote, and the escapes bash honours but
 *   PowerShell or cmd do not (`\"` in double quotes, `\'` in `$'...'`, a
 *   backslash before an operator, a quote or a newline, cmd's `^"`), and a
 *   PowerShell here-string;
 * - characters: a control character other than tab, newline and a CR ending
 *   a line; an invisible or direction-changing one; a curly quote (PowerShell
 *   reads it as a quote) anywhere; any other non-ASCII outside quotes;
 * - here-documents (the body and anything after it is never analysed), and
 *   a line longer than `MAX_ANALYSED_LENGTH`.
 */
export function unmodelledConstructs(command: string): string[] {
  const found: string[] = [];
  const add = (reason: string) => {
    if (!found.includes(reason)) found.push(reason);
  };

  if (command.length > MAX_ANALYSED_LENGTH) add(`line longer than ${MAX_ANALYSED_LENGTH} characters`);
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/.test(command)) add("control character");
  if (/\r(?!\n)/.test(command)) add("carriage return that does not end a line (a line break to PowerShell and cmd)");
  if (/[\p{Cf}\u2028\u2029]/u.test(command)) add("invisible or direction-changing character");
  if (/[\u2018-\u201f\uff02\uff07]/.test(command)) add("curly or fullwidth quote (a quote to PowerShell)");
  if (command.includes("<#")) add("PowerShell block comment");

  const isBlank = (c: string | undefined) => c === undefined || c === " " || c === "\t" || c === "\n" || c === "\r";
  const endsWord = (c: string | undefined) => isBlank(c) || (c !== undefined && ";&|()<>".includes(c));
  /** `${...}` at `i`: flag nested quoting or expansion, and return where a clean one ends. */
  const parameterExpansion = (i: number): number => {
    const close = command.indexOf("}", i + 2);
    if (close === -1 || /['"`\\$]/.test(command.slice(i + 2, close))) {
      add("nested quoting or expansion inside ${...}");
      return i + 1;
    }
    return close;
  };

  let quote: "'" | '"' | "ansi" | null = null;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i]!;
    const next = command[i + 1];
    if (quote === "'") {
      if (ch === "'") quote = null;
      continue;
    }
    if (quote === "ansi") {
      if (ch === "\\") {
        if (next === "'") add("escaped quote in $'...' (not an escape to PowerShell)");
        i++;
      } else if (ch === "'") quote = null;
      continue;
    }
    if (quote === '"') {
      if (ch === "\\") {
        if (next === '"') add('escaped quote in "..." (not an escape to PowerShell or cmd)');
        i++;
      } else if (ch === '"') quote = null;
      else if (ch === "`" || (ch === "$" && next === "(")) add("command substitution");
      else if (ch === "$" && next === "{") i = parameterExpansion(i);
      continue;
    }

    // Outside quotes.
    if (ch === "\\") {
      if (next === "\n") add("line continuation (a line break to PowerShell)");
      else if (next !== undefined && CROSS_SHELL_ESCAPED.has(next)) add("escaped operator or quote (not an escape to PowerShell or cmd)");
      i++;
      continue;
    }
    if (ch === "$" && next === "'") {
      quote = "ansi";
      i++;
      continue;
    }
    if (ch === "$" && next === '"') {
      add('$"..." (locale quoting)');
      quote = '"';
      i++;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    if (ch === "$" && next === "{") {
      i = parameterExpansion(i);
      continue;
    }
    if (ch === "#") add("# outside quotes (a comment)");
    else if (ch === "`") add("command substitution");
    else if (ch === "(" || ch === ")") {
      const prev = command[i - 1];
      if (ch === "(" && prev === "$") add("command substitution or arithmetic");
      else if (ch === "(" && (prev === "<" || prev === ">")) add("process substitution");
      else if (ch === "(" && /^\s*\)/.test(command.slice(i + 1)) && /[A-Za-z0-9_]\s*$/.test(command.slice(0, i))) add("function definition");
      else add("subshell, grouping or pattern");
    } else if ((ch === "{" || ch === "}") && endsWord(command[i - 1]) && endsWord(next)) add("brace group");
    else if (ch === "<" && next === "<") {
      if (command[i + 2] === "<") {
        i += 2;
        continue;
      }
      add(command[i + 2] === "-" ? "<<- here-document" : HEREDOC_TELL);
      i++;
    } else if (ch === "^" && next === '"') add("cmd escape before a quote");
    else if (ch === "@" && (next === "'" || next === '"')) add("PowerShell here-string");
    else if (ch.charCodeAt(0) > 0x7e) add("non-ASCII character outside quotes");
  }
  if (quote) add("unterminated quote");

  for (const seg of splitSegments(command).segments) {
    const words = splitWords(seg);
    for (let k = 0; k < words.length; k++) {
      const raw = words[k]!;
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(raw)) continue;
      const word = raw.replace(/\\/g, "");
      const kind = UNMODELLED_COMMAND_WORDS.get(word);
      if (kind) add(`${kind} (${word})`);
      if (word === "time" && words[k + 1]?.startsWith("-")) add("time with options");
      if (!COMMAND_POSITION_PREFIXES.has(word)) break;
    }
  }
  return found;
}

/**
 * Characters a `\` still escapes. Everything else keeps its backslash, because
 * before an ordinary character a backslash on Windows is a path separator and
 * not an escape: `cd "D:\work\src"` must not become `cd "D:worksrc"`, which
 * resolves to nothing and turns a sanctioned push into an unsanctioned one.
 * `/`, `\`, quotes and the shell's metacharacters stay escapable, so a path
 * written `\/etc\/shadow` still reads as `/etc/shadow` to the secret check.
 */
const ESCAPABLE = new Set(["/", "\\", "'", '"', "`", "$", "&", "|", ";", "<", ">", "(", ")", "{", "}", "[", "]", "*", "?", "!", "#", "~", " ", "\t", "\n", "\r"]);

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
      } else if (ch === "\\" && quote === '"' && i + 1 < segment.length && ESCAPABLE.has(segment[i + 1]!)) {
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
    if (ch === "\\" && i + 1 < segment.length && ESCAPABLE.has(segment[i + 1]!)) {
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

/**
 * The program a verb word names: a path's last component (`/usr/bin/curl`,
 * `C:\Windows\System32\curl.exe`), a shell's escaping backslashes removed
 * (`\curl`, `c\url` both run curl), and a Windows `.exe` dropped.
 */
export function normalizeVerb(word: string): string {
  const unquoted = word.replace(/^(['"])(.*)\1$/, "$2");
  // A Windows path keeps its backslashes as separators; anywhere else a
  // backslash before an ordinary character is an escape the shell removes.
  const windowsPath = /^(?:[A-Za-z]:[\\/]|\\\\|\.\.?\\)/.test(unquoted);
  const text = windowsPath ? unquoted : unquoted.replace(/\\/g, "");
  let base = text.replace(/^.*[\/\\]/, "");
  if (/\.exe$/i.test(base)) base = base.slice(0, -4).toLowerCase();
  return base;
}

/** How a wrapper's own arguments are laid out before the command it runs. */
interface WrapperSpec {
  /** Options that take a separate value (`-u USER`). An attached `-uUSER` or `--opt=v` needs no entry. */
  valued?: string[];
  /** Positional words after the options and before the command (timeout's duration, taskset's mask). */
  positionals?: number;
  /** A positional that is present only when it looks like this (chrt's priority, nice's old `-N`). */
  optionalPositional?: RegExp;
  /** NAME=value words after the options are env assignments for the command (env, sudo). */
  assignments?: boolean;
}

/**
 * Programs that run the command named in their arguments, unchanged in what it
 * does: a privilege switch, a time or resource limit, a scheduler, a buffering
 * or session change, or a re-reader of stdin (`xargs`). Each is seen through
 * by `effectiveCommand`.
 */
const WRAPPERS: Record<string, WrapperSpec> = {
  sudo: { valued: ["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-T", "-U", "--user", "--group", "--close-from", "--chdir", "--host", "--prompt", "--role", "--type", "--command-timeout", "--other-user"], assignments: true },
  doas: { valued: ["-u", "-C"], assignments: true },
  command: {},
  builtin: {},
  exec: { valued: ["-a"] },
  nohup: {},
  time: { valued: ["-f", "-o", "--format", "--output"] },
  nice: { valued: ["-n", "--adjustment"] },
  ionice: { valued: ["-c", "-n", "--class", "--classdata"] },
  env: { valued: ["-u", "-C", "-P", "--unset", "--chdir"], assignments: true },
  timeout: { valued: ["-s", "-k", "--signal", "--kill-after"], positionals: 1 },
  stdbuf: { valued: ["-i", "-o", "-e", "--input", "--output", "--error"] },
  xargs: { valued: ["-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s", "--arg-file", "--delimiter", "--eof", "--replace", "--max-lines", "--max-args", "--max-procs", "--max-chars", "--process-slot-var"] },
  setsid: {},
  chrt: { valued: ["-T", "-P", "-D", "--sched-runtime", "--sched-period", "--sched-deadline"], optionalPositional: /^\d+$/ },
  taskset: { valued: [], positionals: 1 },
  unbuffer: {},
  busybox: {},
  watch: { valued: ["-n", "-q", "--interval", "--equexit"] },
};

/**
 * Shell syntax in front of a command -- a reserved word that opens or
 * continues a compound command, `!`, a brace group's `{`, `coproc` -- is not a
 * program: the command after it is what runs. `effectiveCommand` sees through
 * it, and through a subshell's parentheses, so the deterministic stops see the
 * command inside; such a line is never fast-allowed (`unmodelledConstructs`).
 */
const SYNTAX_PREFIXES = new Set(["!", "{", "if", "then", "elif", "else", "while", "until", "do", "coproc"]);

/** A simple command as it actually runs, once every wrapper in front of it is taken off. */
export interface EffectiveCommand {
  /** `normalizeVerb` of the program that runs; empty when nothing does. */
  verb: string;
  args: string[];
  /** Every NAME=value the line or a wrapper (`env`, `sudo`) sets for it. */
  env: string[];
  /** The wrappers taken off, outermost first, by their normalised names. */
  wrappers: string[];
}

const ASSIGNMENT_WORD = /^[A-Za-z_][A-Za-z0-9_]*=/;

/**
 * See through every wrapper in front of a simple command: `env -i FOO=1 curl`,
 * `timeout 5 curl`, `xargs curl`, `sudo -u bob nice -n 5 curl`, `\curl`,
 * `/usr/bin/curl` all run curl. `env -S 'curl …'` splits its string into the
 * words it runs.
 *
 * Deterministic stops (uploads, self-protection, fast-deny) switch on this, so
 * a wrapper cannot hide the verb they look for. Fast-allow never does: a rule
 * vouches only for the text it names, and seeing through a wrapper there
 * would widen what a rule allows.
 */
export function effectiveCommand(seg: Segment): EffectiveCommand {
  let words = [...seg.words];
  // A subshell's `)` glued to the last word (`(rm x)`) is syntax, not part of
  // the word; its `(` is taken off the first word below.
  const last = words.length - 1;
  if (last >= 0 && /(?:^|[^\\'"])\)+$/.test(seg.text.trimEnd())) {
    const bare = words[last]!.replace(/\)+$/, "");
    if (bare) words[last] = bare;
    else words.pop();
  }
  let i = 0;
  const env: string[] = [];
  const wrappers: string[] = [];
  for (;;) {
    if (i < words.length && words[i]!.startsWith("(")) {
      const bare = words[i]!.replace(/^\(+/, "");
      if (!bare) {
        i++;
        continue;
      }
      words[i] = bare;
    }
    while (i < words.length && ASSIGNMENT_WORD.test(words[i]!)) env.push(words[i++]!);
    if (i >= words.length) return { verb: "", args: [], env, wrappers };
    if (SYNTAX_PREFIXES.has(words[i]!)) {
      i++;
      continue;
    }
    const name = normalizeVerb(words[i]!);
    const spec = WRAPPERS[name];
    if (!spec) break;
    wrappers.push(name);
    i++;
    // The wrapper's own options.
    while (i < words.length) {
      const w = words[i]!;
      if (w === "--") {
        i++;
        break;
      }
      if (!w.startsWith("-") || w === "-") {
        if (w === "-" && name === "env") {
          i++; // `env -` is `env -i`
          continue;
        }
        break;
      }
      if (name === "env" && (w === "-S" || w.startsWith("--split-string") || /^-S./.test(w))) {
        // `env -S 'cmd args'` runs the words of its string.
        const value = w === "-S" || w === "--split-string" ? words[i + 1] ?? "" : w.startsWith("--split-string=") ? w.slice("--split-string=".length) : w.slice(2);
        const consumed = w === "-S" || w === "--split-string" ? 2 : 1;
        words = [...words.slice(0, i), ...splitWords(value), ...words.slice(i + consumed)];
        break;
      }
      if ((spec.valued ?? []).includes(w)) i += 2;
      else i += 1;
    }
    if (spec.assignments) {
      while (i < words.length && ASSIGNMENT_WORD.test(words[i]!)) env.push(words[i++]!);
      if (i < words.length && words[i] === "--") i++;
    }
    for (let p = 0; p < (spec.positionals ?? 0) && i < words.length; p++) i++;
    if (spec.optionalPositional && i < words.length && spec.optionalPositional.test(words[i]!)) i++;
  }
  return { verb: normalizeVerb(words[i]!), args: words.slice(i + 1), env, wrappers };
}

/** `seg` with its verb and arguments replaced by the effective command's, for a rule written against a Segment. */
export function unwrapSegment(seg: Segment): Segment {
  const eff = effectiveCommand(seg);
  return { ...seg, verb: eff.verb, args: eff.args, stripped: [eff.verb, ...eff.args].join(" ") };
}

/** Leading `NAME=value` words before the verb -- the env assignments that
 * apply to this one simple command. Exported so a check that cares about a
 * specific variable (self-protection's `AUTO_CLASSIFIER_*` guard) does not
 * re-derive this from scratch. */
export function envAssignments(seg: Segment): string[] {
  return seg.words.filter((w) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(w) && seg.words.indexOf(w) < seg.words.indexOf(seg.verb));
}

/**
 * What one redirect does:
 * - `write`: opens a file for writing (`>`, `>>`, `>|`, `&>`, `&>>`, `<>`,
 *   `>&word` where word is not an fd number, each with an optional `N` or
 *   `{name}` prefix);
 * - `null`: the same, into the literal path `/dev/null`;
 * - `fd`: duplicates, moves or closes a descriptor (`2>&1`, `>&2`, `3>&-`,
 *   `3>&2-`, `<&0`);
 * - `read`: opens a file for reading (`<`);
 * - `heredoc` / `herestring`: feeds the command text from the line itself;
 * - `unparsed`: syntax the scanner cannot pin down (no target, a process
 *   substitution, `<&word`, a stray `&`, `|` or `;`). Counted as a write.
 */
export type RedirectKind = "write" | "null" | "fd" | "read" | "heredoc" | "herestring" | "unparsed";

export interface Redirect {
  /** The operator as written, its fd or `{name}` prefix included (`2>`, `&>>`, `{fd}>`, `1<>`). */
  op: string;
  /** The word after the operator, quotes and escapes removed; "" when there is none. */
  target: string;
  /** The target names one path as written: no `$`, backtick, glob, brace or leading `~` for the shell to expand. */
  literal: boolean;
  kind: RedirectKind;
  /** Span of operator and target in the scanned text. */
  start: number;
  end: number;
}

/** A redirect that may create, truncate or append to a file, or that could not be read well enough to say it does not. */
export function redirectWrites(r: Redirect): boolean {
  return r.kind === "write" || r.kind === "unparsed";
}

/** Characters that end a redirect's target word when unquoted. */
const WORD_END = new Set([" ", "\t", "\n", "\r", "<", ">", "&", "|", ";", "(", ")"]);

/** Read one shell word starting at `i`: its value with quotes and escapes removed, and whether it is literal. */
function readWord(text: string, i: number): { value: string; literal: boolean; end: number; present: boolean } {
  let value = "";
  let literal = true;
  let present = false;
  const start = i;
  while (i < text.length) {
    const ch = text[i]!;
    if (WORD_END.has(ch)) break;
    if (ch === "\\" && (text[i + 1] === ">" || text[i + 1] === "<")) break; // see scanRedirects
    present = true;
    if (ch === "$" && text[i + 1] === "'") {
      const end = endOfAnsiQuote(text, i + 2);
      value += text.slice(i + 2, end - 1);
      literal = false;
      i = end;
      continue;
    }
    if (ch === "'") {
      const close = text.indexOf("'", i + 1);
      if (close === -1) return { value: value + text.slice(i + 1), literal: false, end: text.length, present };
      value += text.slice(i + 1, close);
      i = close + 1;
      continue;
    }
    if (ch === '"') {
      i++;
      while (i < text.length && text[i] !== '"') {
        const c = text[i]!;
        if (c === "\\" && i + 1 < text.length && ESCAPABLE.has(text[i + 1]!)) {
          value += text[i + 1];
          i += 2;
          continue;
        }
        if (c === "$" || c === "`") literal = false;
        value += c;
        i++;
      }
      if (i >= text.length) literal = false; // unterminated
      i++;
      continue;
    }
    if (ch === "\\" && i + 1 < text.length && ESCAPABLE.has(text[i + 1]!)) {
      value += text[i + 1];
      i += 2;
      continue;
    }
    if (ch === "$" || ch === "`" || ch === "*" || ch === "?" || ch === "[" || ch === "{" || (ch === "~" && i === start)) literal = false;
    value += ch;
    i++;
  }
  return { value, literal, end: i, present };
}

/** The index just past the `'` closing an ANSI-C string whose body starts at `i`. */
function endOfAnsiQuote(text: string, i: number): number {
  while (i < text.length && text[i] !== "'") i += text[i] === "\\" ? 2 : 1;
  return i + 1;
}

/** Whether position `j` starts a word (the fd prefix of a redirect must). */
function atWordStart(text: string, j: number): boolean {
  return j === 0 || /\s/.test(text[j - 1]!);
}

/**
 * Every redirect in one simple command's text, found by a quote-aware scan
 * rather than a regex, so an operator glued to the word before it
 * (`journalctl>x`, `2>&1>x`, `{fd}>x`, `1<>x`) is found exactly as a spaced
 * one is. Quoted operators (`'>'`, `">"`, `$'>'`) are data and are skipped; a
 * backslash-escaped one is counted, because only bash reads it as escaped.
 * An unquoted `>` or `<` anywhere is a redirect, which is what the shell makes
 * of it outside `[[ ]]` and arithmetic -- where reading it as one only ever
 * adds a tell.
 *
 * This is the one redirect parser: the fast-allow tells, self-protection, the
 * sensitive-write check on a scratch redirect, landed-script trust and the
 * denial key all read it.
 */
export function scanRedirects(text: string): Redirect[] {
  const out: Redirect[] = [];
  let i = 0;
  while (i < text.length) {
    const ch = text[i]!;
    if (ch === "\\") {
      // Bash reads `\>` as a literal `>`; PowerShell and cmd read the
      // backslash as a path character and the `>` as a redirect
      // (`C:\>out.txt`). The redirect reading is the one that can write.
      i += text[i + 1] === ">" || text[i + 1] === "<" ? 1 : 2;
      continue;
    }
    if (ch === "$" && text[i + 1] === "'") {
      i = endOfAnsiQuote(text, i + 2);
      continue;
    }
    if (ch === "'") {
      const close = text.indexOf("'", i + 1);
      i = close === -1 ? text.length : close + 1;
      continue;
    }
    if (ch === '"') {
      i++;
      while (i < text.length && text[i] !== '"') i += text[i] === "\\" ? 2 : 1;
      i++;
      continue;
    }
    const amp = ch === "&" && text[i + 1] === ">";
    if (ch !== ">" && ch !== "<" && !amp) {
      // The splitter never leaves these inside a simple command; if one is
      // here, the line is not what this scan assumes.
      if (ch === "&" || ch === "|" || ch === ";") out.push({ op: ch, target: "", literal: false, kind: "unparsed", start: i, end: i + 1 });
      i++;
      continue;
    }

    let start = i;
    if (!amp) {
      let j = i;
      while (j > 0 && /[0-9]/.test(text[j - 1]!)) j--;
      if (j < i && atWordStart(text, j)) start = j;
      else if (text[i - 1] === "}") {
        const m = /\{[A-Za-z_][A-Za-z0-9_]*\}$/.exec(text.slice(0, i));
        if (m && atWordStart(text, m.index)) start = m.index;
      }
    }
    const ops = amp ? ["&>>", "&>"] : ch === "<" ? ["<<<", "<<-", "<<", "<>", "<&", "<"] : [">>", ">|", ">&", ">"];
    const base = ops.find((o) => text.startsWith(o, i))!;
    const op = text.slice(start, i) + base;
    let k = i + base.length;
    while (k < text.length && (text[k] === " " || text[k] === "\t")) k++;

    if (text[k] === "(") {
      // `>(cmd)` / `<(cmd)`: a process substitution, not a path.
      out.push({ op, target: "", literal: false, kind: "unparsed", start, end: k + 1 });
      i = k + 1;
      continue;
    }
    const word = readWord(text, k);
    const target = word.value;
    let kind: RedirectKind;
    if (!word.present) kind = "unparsed";
    else if (base === "<<" || base === "<<-") kind = "heredoc";
    else if (base === "<<<") kind = "herestring";
    else if (base === "<") kind = "read";
    else if (base === ">&" || base === "<&") {
      if (word.literal && /^(?:\d+-?|-)$/.test(target)) kind = "fd";
      else if (base === "<&") kind = "unparsed";
      else kind = word.literal && target === "/dev/null" ? "null" : "write";
    } else kind = word.literal && target === "/dev/null" ? "null" : "write";
    out.push({ op, target, literal: word.literal, kind, start, end: word.end });
    i = Math.max(word.end, i + base.length);
  }
  return out;
}

/** The file targets a simple command's redirects write to (fd duplication and
 * /dev/null excluded, neither is a write). Exported for the same reason as
 * `envAssignments`: the self-protection guard needs the actual target path,
 * not just the tell string reported for it. */
export function redirectTargets(seg: Segment): string[] {
  return scanRedirects(seg.text)
    .filter((r) => r.kind === "write" && r.target !== "")
    .map((r) => r.target);
}

/** The tell a writing redirect is reported under. Every one starts with `redirect`. */
export function redirectTell(r: Redirect): string {
  if (r.kind === "unparsed") return `redirect the gate cannot parse (${r.op}${r.target})`;
  return r.literal ? `redirect to ${r.target}` : `redirect to ${r.target} (not a literal path)`;
}

/** Whether a tell is one `redirectTell` produced. */
export function isRedirectTell(tell: string): boolean {
  return tell.startsWith("redirect ");
}

/** Everything about one simple command that makes a read-only verb not read-only. Redirects are reported by `analyzeCommand`, once per segment. */
function writeTells(seg: Segment): string[] {
  const tells: string[] = [];
  const verb = seg.verb.replace(/^.*\//, ""); // /usr/bin/tee -> tee

  for (const a of envAssignments(seg)) {
    const name = a.slice(0, a.indexOf("="));
    if (HIJACK_ENV.test(name)) tells.push(`${name}= prefix`);
  }

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
  if (verb === "git") {
    for (let i = 0; i < seg.args.length; i++) {
      const a = seg.args[i]!;
      if (a === "-c") {
        const next = seg.args[i + 1] ?? "";
        if (!/^((user|author|committer)\.(name|email|signingkey)|commit\.gpgsign)=/i.test(next)) {
          tells.push("git with -c/--output/--exec-path/--git-dir");
          break;
        }
      } else if (a.startsWith("-c") && !/^-c((user|author|committer)\.(name|email|signingkey)|commit\.gpgsign)=/i.test(a)) {
        tells.push("git with -c/--output/--exec-path/--git-dir");
        break;
      }
    }
    if (has((a) => a.startsWith("--output") || a.startsWith("--exec-path") || a === "--git-dir")) {
      tells.push("git with -c/--output/--exec-path/--git-dir");
    }
  }
  // Each of these runs a program: one named on the line (-O / --open-files-in-pager)
  // or one the repository's own config names (--ext-diff, --textconv).
  if (verb === "git" && has((a) => /^-O/.test(a) || a.startsWith("--open-files-in-pager") || a === "--ext-diff" || a === "--textconv")) tells.push("git runs a pager, diff driver or textconv program");
  if (verb === "curl") {
    if (has((a) => a === "-O" || a === "--remote-name" || a.startsWith("--remote-name="))) {
      tells.push("curl -O writes to a file");
    }
    for (let i = 0; i < seg.args.length; i++) {
      const a = seg.args[i]!;
      if (a === "-o" && seg.args[i + 1] !== "/dev/null") {
        tells.push("curl -o writes to a file");
        break;
      }
      if (a === "-D" && seg.args[i + 1] !== "-") {
        tells.push("curl -D writes to a file");
        break;
      }
      if (a === "--dump-header" && seg.args[i + 1] !== "-") {
        tells.push("curl --dump-header writes to a file");
        break;
      }
      if (a === "--output" && seg.args[i + 1] !== "/dev/null") {
        tells.push("curl --output writes to a file");
        break;
      }
    }
    if (has((a) => (a.startsWith("-o") && a !== "-o" && a !== "-o/dev/null") || (a.startsWith("--output=") && a !== "--output=/dev/null"))) {
      tells.push("curl -o writes to a file");
    }
    if (has((a) => (a.startsWith("-D") && a !== "-D" && a !== "-D-") || (a.startsWith("--dump-header=") && a !== "--dump-header=-"))) {
      tells.push("curl -D writes to a file");
    }
    if (has((a) => a === "-T" || a.startsWith("-T") || a === "--upload-file" || a.startsWith("--upload-file="))) {
      tells.push("curl uploads a file");
    }
  }
  if (has((a) => a.startsWith("--output") || a.startsWith("--out-file") || a.startsWith("--log-file"))) {
    if (verb !== "git" && verb !== "curl") tells.push(`${verb} --output`);
  }
  if (verb === "tail" && has((a) => /^-[a-zA-Z]*f/.test(a) || a === "--follow")) tells.push("tail -f never returns");
  if (verb === "journalctl" && has((a) => /^--(?:vacuum-|rotate|flush|sync|relinquish|setup-keys)/.test(a))) tells.push("journalctl maintenance flag");
  if (verb === "journalctl" && has((a) => /^-[a-zA-Z]*f/.test(a) || a === "--follow")) tells.push("journalctl -f never returns");
  // PowerShell script blocks and expression evaluation run arbitrary code
  // inside an otherwise read-only cmdlet.
  if (seg.words.some((w) => /^(?:iex|invoke-expression|invoke-command|icm|start-process|saps)$/i.test(w))) tells.push("PowerShell evaluates code");
  if (/^[A-Za-z]+-[A-Za-z]+$/.test(verb) && /[{}]/.test(seg.text)) tells.push("PowerShell script block");
  // Raw tokens too: the splitter normalizes shell escapes (`\ ` -> a space,
  // `\/` -> `/`, quotes dropped), so a path written with them reads differently
  // as parsed arguments than as text; scan both forms for a secret.
  const rawTokens = seg.text.split(/\s+/).slice(1).map((t) => t.replace(/^['"]|['"]$/g, ""));
  // A file a redirect opens is read (or written) as surely as an argument
  // is, glued to a flag (`wc -l<~/.aws/credentials`) or not.
  const redirected = scanRedirects(seg.text).filter((r) => r.target !== "" && (r.kind === "read" || r.kind === "write")).map((r) => r.target);
  const secret = [...seg.args, ...rawTokens, ...redirected].find((a) => !a.startsWith("-") && SECRET_PATH.test(a.replace(/^~/, "/home/x").replace(/\\/g, "/")));
  if (secret) tells.push(`reads a secret-looking path (${secret})`);
  return tells;
}
