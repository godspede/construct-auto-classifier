import path from "node:path";
import { analyzeCommand, scanRedirects, unwrapSegment, type Segment } from "./command-shape.js";
import { defaultGit, type GitRunner } from "../context/script-provenance.js";

/**
 * Uploads to a destination nobody sanctioned are decided here, before the
 * model, so that stopping one never depends on how confident the model is.
 *
 * The worry is a confused or injected agent sending the project's code, data
 * or credentials to some random site. Reading a website is not that and stays
 * free: only command shapes that SEND something are looked at (curl with a
 * body or an upload, wget posting, scp/rsync/sftp to a remote host, nc/socat
 * fed input, git pointing a remote at or pushing to a URL, gh writing to a
 * repository). Each destination is checked against `sanctionedRemotes`;
 * loopback is always sanctioned. A destination that cannot be worked out (a
 * `$URL`, a remote whose URL git will not say) counts as unsanctioned.
 *
 * This only ever stops a command. A sanctioned destination proves nothing
 * about what is sent there, so everything it lets past still goes through the
 * fast rules and the model.
 */

/** One `sanctionedRemotes` entry, parsed. */
export type SanctionedEntry =
  | { kind: "host"; host: string }
  | { kind: "suffix"; suffix: string }
  | { kind: "path"; host: string; prefix: string }
  | { kind: "cidr"; base: number; bits: number };

/** A place a command sends to: a host and, where the command names one, a path on it. */
export interface Destination {
  host: string;
  path?: string;
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0", "ip6-localhost"]);

function ipv4ToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/**
 * Parse one pattern: an exact host (`gitea.example.ts.net`), a `*.suffix`
 * wildcard, a host plus path prefix (`github.com/octo-org/`), or an IPv4 CIDR
 * range (`100.64.0.0/10`). No scheme, no port. Anything else is dropped, so a
 * list read from a file can only ever contribute host patterns.
 */
export function parseSanctionedEntry(raw: unknown): SanctionedEntry | null {
  if (typeof raw !== "string") return null;
  const s = raw.trim().toLowerCase();
  if (!s || /\s|:\/\/|[?#@]/.test(s)) return null;
  const cidr = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(s);
  if (cidr) {
    const base = ipv4ToInt(cidr[1]);
    const bits = Number(cidr[2]);
    return base === null || bits > 32 ? null : { kind: "cidr", base, bits };
  }
  const slash = s.indexOf("/");
  const host = slash === -1 ? s : s.slice(0, slash);
  if (!/^(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*$/.test(host) || host.includes(":")) return null;
  if (slash !== -1) {
    if (host.startsWith("*.")) return null;
    if (s.slice(slash).split("/").includes("..")) return null;
    const prefix = path.posix.normalize(s.slice(slash));
    if (prefix === "/") return { kind: "host", host };
    return { kind: "path", host, prefix };
  }
  return host.startsWith("*.") ? { kind: "suffix", suffix: host.slice(1) } : { kind: "host", host };
}

export function parseSanctioned(list: readonly unknown[] | undefined): SanctionedEntry[] {
  return (list ?? []).map(parseSanctionedEntry).filter((e): e is SanctionedEntry => e !== null);
}

function isLoopback(host: string): boolean {
  if (LOOPBACK_HOSTS.has(host)) return true;
  const n = ipv4ToInt(host);
  return n !== null && n >>> 24 === 127;
}

/**
 * GitHub's API and upload hosts name the repository in the path
 * (`/repos/<owner>/<repo>/...`); a write there is a write to that repository,
 * so it is matched as `github.com/<owner>/<repo>/...`.
 */
function githubRepoForm(d: Destination): Destination | null {
  if (d.host !== "api.github.com" && d.host !== "uploads.github.com") return null;
  const m = /^\/?repos\/([^/]+)\/([^/]+)(\/.*)?$/.exec(d.path ?? "");
  return m ? { host: "github.com", path: `/${m[1]}/${m[2]}${m[3] ?? ""}` } : null;
}

export function isSanctioned(d: Destination, entries: readonly SanctionedEntry[]): boolean {
  const host = d.host.toLowerCase().replace(/^\[|\]$/g, "");
  if (isLoopback(host)) return true;
  const rawPath = d.path === undefined ? undefined : path.posix.normalize("/" + d.path.replace(/^\/+/, "")).toLowerCase();
  const forms: Destination[] = [{ host, path: rawPath }];
  const gh = githubRepoForm({ host, path: rawPath });
  if (gh) forms.push({ host: gh.host, path: gh.path?.toLowerCase() });
  return forms.some((f) =>
    entries.some((e) => {
      switch (e.kind) {
        case "host":
          return f.host === e.host;
        case "suffix":
          return f.host.endsWith(e.suffix);
        case "cidr": {
          const n = ipv4ToInt(f.host);
          if (n === null) return false;
          const mask = e.bits === 0 ? 0 : (~0 << (32 - e.bits)) >>> 0;
          return (n & mask) === (e.base & mask);
        }
        case "path": {
          if (f.host !== e.host || f.path === undefined || f.path.split("/").includes("..")) return false;
          const prefix = e.prefix.endsWith("/") ? e.prefix : e.prefix + "/";
          return f.path === e.prefix || (f.path + "/").startsWith(prefix);
        }
      }
    })
  );
}

/** `local` for a path on this machine; null when the text names no destination at all. */
export function parseDestination(text: string): Destination | "local" | null {
  const t = text.trim();
  if (!t) return null;
  if (/^file:\/\//i.test(t)) return "local";
  const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(t);
  if (scheme) {
    try {
      const u = new URL(t.replace(/^git\+/i, ""));
      if (!u.hostname) return null;
      return { host: u.hostname.toLowerCase().replace(/^\[|\]$/g, ""), path: decodeURIComponent(u.pathname) };
    } catch {
      return null;
    }
  }
  if (/^(?:\/|\.{1,2}(?:\/|$)|~)/.test(t)) return "local";
  // scp-like `[user@]host:path` (a one-letter "host" is a Windows drive)
  const scp = /^(?:[^@/\s:]+@)?(\[[^\]]+\]|[^:/\s@]+):(.*)$/.exec(t);
  if (scp && scp[1].length > 1) return { host: scp[1].toLowerCase().replace(/^\[|\]$/g, ""), path: "/" + scp[2].replace(/^\/+/, "") };
  return null;
}

/** A bare `host[:port]/path` as curl and wget accept it. */
function parseLooseUrl(text: string): Destination | null {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) {
    const d = parseDestination(text);
    return d && d !== "local" ? d : null;
  }
  if (!/^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:\/|$)|^(?:localhost|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?:\/|$)/i.test(text)) return null;
  const d = parseDestination("http://" + text);
  return d && d !== "local" ? d : null;
}

export interface UploadContext {
  cwd?: string;
  sanctioned: readonly SanctionedEntry[];
  git?: GitRunner;
  /** The whole command line, for shapes a single segment cannot show (a pipe into nc). */
  line?: string;
}

interface Finding {
  what: string;
  /** How the destination reads in the reason. */
  dest: string;
  /** The destination itself; null or absent when it cannot be worked out. */
  d?: Destination | "local" | null;
}

function describe(d: Destination | null): string {
  return d ? `${d.host}${d.path && d.path !== "/" ? d.path : ""}` : "a destination the gate cannot work out";
}

/** The value of `--flag value` / `--flag=value` / `-f value`, or undefined. */
function flagValues(args: string[], names: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    for (const n of names) {
      if (a === n && i + 1 < args.length) out.push(args[i + 1]);
      else if (n.startsWith("--") && a.startsWith(n + "=")) out.push(a.slice(n.length + 1));
    }
  }
  return out;
}

function hasFlag(args: string[], names: string[]): boolean {
  return args.some((a) => names.some((n) => a === n || (n.startsWith("--") && a.startsWith(n + "="))));
}

/** Positional arguments, skipping flags and the values of the flags named in `valued`. */
function positionals(args: string[], valued: Set<string>): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") {
      out.push(...args.slice(i + 1));
      break;
    }
    if (a.startsWith("-") && a.length > 1) {
      if (valued.has(a)) i++;
      continue;
    }
    out.push(a);
  }
  return out;
}

const CURL_UPLOAD_LONG = ["--upload-file", "--form", "--form-string", "--data", "--data-binary", "--data-raw", "--data-ascii", "--data-urlencode", "--json"];
const CURL_VALUED = new Set([
  "-T", "-F", "-d", "-H", "-o", "-u", "-X", "-e", "-A", "-b", "-c", "-K", "-m", "-w", "-x", "-r", "-E", "-U", "-Y", "-y", "-z", "-C",
  "--upload-file", "--form", "--form-string", "--data", "--data-binary", "--data-raw", "--data-ascii", "--data-urlencode", "--json",
  "--header", "--output", "--user", "--request", "--referer", "--user-agent", "--cookie", "--cookie-jar", "--config", "--max-time",
  "--write-out", "--proxy", "--range", "--cert", "--key", "--cacert", "--connect-timeout", "--retry", "--resolve", "--connect-to",
  "--oauth2-bearer", "--url",
]);

function curlFinding(seg: Segment): Finding[] {
  const a = seg.args;
  const shortCluster = a.some((w) => /^-[a-zA-Z]+$/.test(w) && /[TFd]/.test(w));
  if (!shortCluster && !hasFlag(a, CURL_UPLOAD_LONG)) return [];
  const urls = [...flagValues(a, ["--url"]), ...positionals(a, CURL_VALUED)];
  const dests = urls.map(parseLooseUrl).filter((d): d is Destination => d !== null);
  if (dests.length === 0) return [{ what: "curl sends data to", dest: describe(null) }];
  return dests.map((d) => ({ what: "curl sends data to", dest: describe(d), d }));
}

const WGET_UPLOAD = ["--post-file", "--post-data", "--body-file", "--body-data"];
const WGET_VALUED = new Set(["-O", "-o", "-a", "-e", "-i", "-P", "-U", "-t", "-T", "-w", "--header", "--user", "--password", "--output-document", "--output-file", "--user-agent", "--method", ...WGET_UPLOAD]);

function wgetFinding(seg: Segment): Finding[] {
  if (!hasFlag(seg.args, WGET_UPLOAD)) return [];
  const dests = positionals(seg.args, WGET_VALUED).map(parseLooseUrl).filter((d): d is Destination => d !== null);
  if (dests.length === 0) return [{ what: "wget posts data to", dest: describe(null) }];
  return dests.map((d) => ({ what: "wget posts data to", dest: describe(d), d }));
}

const SCP_VALUED = new Set(["-P", "-i", "-o", "-F", "-l", "-c", "-J", "-S", "-D", "-X"]);
const RSYNC_VALUED = new Set(["-e", "--rsh", "-f", "--filter", "--exclude", "--include", "--exclude-from", "--include-from", "--files-from", "-T", "--temp-dir", "--port", "--password-file", "--log-file", "-B", "--block-size"]);

function remoteArg(text: string): Destination | null {
  if (/^rsync:\/\//i.test(text)) {
    const d = parseDestination(text);
    return d && d !== "local" ? d : null;
  }
  const mod = /^(?:[^@/\s:]+@)?([^:/\s@]+)::(.*)$/.exec(text);
  if (mod) return { host: mod[1].toLowerCase(), path: "/" + mod[2] };
  const d = parseDestination(text);
  return d && d !== "local" ? d : null;
}

function copyFinding(seg: Segment, verb: "scp" | "rsync"): Finding[] {
  const pos = positionals(seg.args, verb === "scp" ? SCP_VALUED : RSYNC_VALUED);
  if (pos.length < 2) return [];
  const dest = remoteArg(pos[pos.length - 1]);
  return dest ? [{ what: `${verb} copies files to`, dest: describe(dest), d: dest }] : [];
}

function sftpFinding(seg: Segment): Finding[] {
  const pos = positionals(seg.args, new Set(["-b", "-P", "-i", "-o", "-F", "-l", "-B", "-R", "-S", "-J", "-D", "-c", "-X"]));
  if (pos.length === 0) return [];
  const m = /^(?:[^@/\s]+@)?(\[[^\]]+\]|[^:/\s@]+)/.exec(pos[0].replace(/^sftp:\/\//i, ""));
  if (!m) return [];
  const d = { host: m[1].toLowerCase().replace(/^\[|\]$/g, "") };
  return [{ what: "sftp opens a file transfer to", dest: describe(d), d }];
}

function netcatFinding(seg: Segment, line: string): Finding[] {
  const a = seg.args;
  if (a.some((w) => /^-[a-zA-Z]*[zl][a-zA-Z]*$/.test(w) || w === "--listen")) return [];
  // Fed by a pipe: a `|` earlier on the line whose simple command names this
  // verb, wrapped or not (`| nc host`, `| timeout 5 nc host`, `| /bin/nc host`).
  const verb = seg.verb.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pipedIn = new RegExp(`\\|[^|;&\\n]*?(?:^|[\\s/\\\\'"])${verb}(?:\\.exe)?(?=[\\s'"]|$)`, "i").test(line);
  // Fed from a file, a here-string or a here-document, glued or spaced
  // (`nc host 4444<secrets.txt`): the same scan every other redirect check reads.
  const redirectedIn = scanRedirects(seg.text).some((r) => /^(?:\d+|\{[A-Za-z_][A-Za-z0-9_]*\})?</.test(r.op));
  if (!pipedIn && !redirectedIn) return [];
  const pos = positionals(a, new Set(["-p", "-s", "-w", "-i", "-q", "-x", "-X", "-e", "-c", "-W", "-T"])).filter((w) => !/^\d+$/.test(w));
  const d = pos[0] ? { host: pos[0].toLowerCase().replace(/^\[|\]$/g, "") } : null;
  return [{ what: `${seg.verb} sends its input to`, dest: describe(d), d }];
}

function socatFinding(seg: Segment): Finding[] {
  const out: Finding[] = [];
  for (const w of seg.args) {
    const m = /^(?:tcp[46]?|tcp-connect|openssl|ssl|udp[46]?|udp-sendto|sctp[46]?)[^:]*:([^:,]+)/i.exec(w);
    if (m) {
      const d = { host: m[1].toLowerCase() };
      out.push({ what: "socat relays data to", dest: describe(d), d });
    }
  }
  return out;
}

const GIT_GLOBAL_VALUED = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"]);
const PUSH_VALUED = new Set(["-o", "--push-option", "--receive-pack", "--exec", "--signed"]);

/** A git remote's push URL, or null when git cannot say (no such remote, not a repo). */
export function resolveRemoteUrl(git: GitRunner, cwd: string, remote: string): string | null {
  const r = git(["remote", "get-url", "--push", remote], cwd);
  return r.status === 0 && r.stdout ? r.stdout.split("\n")[0].trim() : null;
}

/** The remote a bare `git push` would use: pushRemote, pushDefault, the branch's remote, else origin. */
function defaultPushRemote(git: GitRunner, cwd: string): string {
  const cfg = (key: string) => {
    const r = git(["config", "--get", key], cwd);
    return r.status === 0 && r.stdout ? r.stdout.trim() : null;
  };
  const branch = git(["branch", "--show-current"], cwd);
  const b = branch.status === 0 ? branch.stdout.trim() : "";
  return (b && cfg(`branch.${b}.pushRemote`)) || cfg("remote.pushDefault") || (b && cfg(`branch.${b}.remote`)) || "origin";
}

function urlOrRemote(target: string, git: GitRunner, cwd: string | undefined): { d: Destination | "local" | null; shown: string } {
  const direct = parseDestination(target);
  if (direct) return { d: direct, shown: target };
  if (!/^[A-Za-z0-9_.\/-]+$/.test(target)) return { d: null, shown: target };
  const url = cwd ? resolveRemoteUrl(git, cwd, target) : null;
  if (!url) return { d: null, shown: `remote "${target}" (its URL cannot be read)` };
  return { d: parseDestination(url), shown: `remote "${target}"` };
}

function gitFinding(seg: Segment, ctx: UploadContext, cwd: string | undefined, vars: Map<string, string>): { findings: Finding[]; cwd: string | undefined } {
  const git = ctx.git ?? defaultGit;
  const a = seg.args;
  let i = 0;
  let dir = cwd;
  while (i < a.length && a[i].startsWith("-")) {
    if (a[i] === "-C" && i + 1 < a.length) {
      const target = expandVars(a[i + 1], vars);
      dir = target === undefined ? undefined : resolveDir(dir, target);
    }
    if (GIT_GLOBAL_VALUED.has(a[i])) i++;
    i++;
  }
  const sub = a[i];
  const rest = a.slice(i + 1);
  const out: Finding[] = [];
  if (sub === "remote" && (rest[0] === "add" || rest[0] === "set-url")) {
    const pos = positionals(rest.slice(1), new Set(["-t", "-m"]));
    const url = pos[1];
    if (url) {
      const d = parseDestination(url);
      out.push({ what: `git remote ${rest[0]} points a remote at`, dest: d && d !== "local" ? describe(d) : url, d: d ?? null });
    }
  } else if (sub === "push") {
    const repoFlag = flagValues(rest, ["--repo"])[0];
    const pos = positionals(rest, PUSH_VALUED);
    const target = repoFlag ?? pos[0];
    const resolved = target ? urlOrRemote(target, git, dir) : dir ? urlOrRemote(defaultPushRemote(git, dir), git, dir) : { d: null, shown: "the default remote" };
    out.push({ what: "git push sends commits to", dest: resolved.d && resolved.d !== "local" ? describe(resolved.d) : resolved.shown, d: resolved.d });
  }
  return { findings: out, cwd: dir };
}

const GH_WRITES: Record<string, Set<string>> = {
  issue: new Set(["create", "comment", "edit"]),
  pr: new Set(["create", "comment", "edit", "review"]),
  release: new Set(["create", "upload", "edit"]),
};

/** `OWNER/REPO` or `HOST/OWNER/REPO` as gh's `-R` takes it. */
function ghRepoDest(value: string): Destination | null {
  const parts = value.replace(/^https?:\/\//i, "").split("/").filter(Boolean);
  if (parts.length === 2) return { host: "github.com", path: `/${parts[0]}/${parts[1]}` };
  if (parts.length >= 3) return { host: parts[0].toLowerCase(), path: `/${parts[1]}/${parts[2]}` };
  return null;
}

function ghFinding(seg: Segment, ctx: UploadContext, cwd: string | undefined): Finding[] {
  const a = seg.args;
  const repoFlag = flagValues(a, ["-R", "--repo"])[0];
  const pos = positionals(a, new Set(["-R", "--repo", "-b", "--body", "-t", "--title", "-F", "--body-file", "-f", "--field", "--raw-field", "-X", "--method", "--input", "-H", "--header", "-q", "--jq", "--hostname", "-a", "--assignee", "-l", "--label", "-B", "--base", "-H", "--head", "-m", "--milestone", "-d", "--desc", "--notes", "-n", "--notes-file", "--target", "--source", "-r", "--remote", "-p", "--project", "-c", "--clone"]));
  const [group, sub] = pos;
  const current = (): Destination | null => {
    if (repoFlag) return ghRepoDest(repoFlag);
    if (!cwd) return null;
    const url = resolveRemoteUrl(ctx.git ?? defaultGit, cwd, "origin");
    const d = url ? parseDestination(url) : null;
    return d && d !== "local" ? d : null;
  };
  if (group === "gist" && (sub === "create" || sub === "edit" || sub === "new")) {
    // A gist is a new public-by-link paste on GitHub's own host; no entry sanctions it.
    return [{ what: `gh gist ${sub} uploads to`, dest: "a GitHub gist (never sanctioned)", d: { host: "gist.github.com" } }];
  }
  if (group === "repo" && sub === "create" && hasFlag(a, ["--push", "--source", "-s"])) {
    const d = pos[2] && pos[2].includes("/") ? ghRepoDest(pos[2]) : null;
    return [{ what: "gh repo create pushes to", dest: describe(d), d }];
  }
  if (group && sub && GH_WRITES[group]?.has(sub)) {
    const d = current();
    return [{ what: `gh ${group} ${sub} writes to`, dest: describe(d), d }];
  }
  if (group === "api") {
    const method = (flagValues(a, ["-X", "--method"])[0] ?? "").toUpperCase();
    const hasBody = hasFlag(a, ["-f", "-F", "--field", "--raw-field", "--input"]);
    if ((method && method !== "GET") || (!method && hasBody)) {
      const endpoint = (pos[1] ?? "").replace(/^\/+/, "");
      const host = flagValues(a, ["--hostname"])[0] ?? "api.github.com";
      const d: Destination | null = endpoint ? { host: host.toLowerCase(), path: "/" + endpoint.split("?")[0] } : null;
      return [{ what: `gh api ${method || "POST"} writes to`, dest: describe(d), d }];
    }
  }
  return [];
}

/** `$NAME` / `${NAME}` from the line's own simple assignments (and HOME); undefined when any is unknown. */
export function expandVars(text: string, vars: Map<string, string>): string | undefined {
  if (/`|\$\(/.test(text)) return undefined;
  let unknown = false;
  const out = text.replace(/\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))/g, (_, a, b) => {
    const name = a ?? b;
    const v = vars.get(name) ?? (name === "HOME" ? process.env.HOME : undefined);
    if (v === undefined) unknown = true;
    return v ?? "";
  });
  return unknown || out.includes("$") ? undefined : out;
}

export function resolveDir(cwd: string | undefined, target: string): string | undefined {
  if (!target || /[$`]/.test(target)) return undefined;
  const home = process.env.HOME;
  const t = target === "~" ? home : target.startsWith("~/") && home ? path.join(home, target.slice(2)) : target;
  if (!t) return undefined;
  if (path.isAbsolute(t)) return t;
  return cwd ? path.resolve(cwd, t) : undefined;
}

export interface UploadCheck {
  /** Why the first unsanctioned upload is one, or null when there is none. */
  unsanctioned: string | null;
  /** Every upload the command makes that goes somewhere sanctioned, described. */
  sanctioned: string[];
}

/** A simple command with the directory it runs in and the line's variables so far. */
export interface WalkedSegment {
  seg: Segment;
  /** Where this simple command runs, after any `cd` before it; undefined when that cannot be worked out. */
  cwd: string | undefined;
  vars: Map<string, string>;
}

/**
 * Walk a line's simple commands in order, following `cd` and simple
 * `NAME=value` / `export NAME=value` assignments, so `WT=$HOME/work/x` then
 * `cd "$WT"` puts what follows in `$HOME/work/x`. Assignment and `cd`
 * segments themselves are not yielded.
 */
export function walkSegments(command: string, startCwd: string | undefined): WalkedSegment[] {
  const shape = analyzeCommand(command);
  let cwd = startCwd;
  const vars = new Map<string, string>();
  const out: WalkedSegment[] = [];
  for (const seg of shape.segments) {
    const assigns = seg.verb === "export" ? seg.args : seg.verb === "" ? seg.words : [];
    if (assigns.length && assigns.every((w) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(w))) {
      for (const w of assigns) {
        const eq = w.indexOf("=");
        const v = expandVars(w.slice(eq + 1), vars);
        if (v === undefined) vars.delete(w.slice(0, eq));
        else vars.set(w.slice(0, eq), v);
      }
      continue;
    }
    if (seg.verb === "cd") {
      const target = seg.args.filter((x) => !x.startsWith("-"))[0];
      const expanded = target === undefined ? process.env.HOME : expandVars(target, vars);
      cwd = expanded === undefined ? undefined : resolveDir(cwd, expanded);
      continue;
    }
    out.push({ seg, cwd, vars: new Map(vars) });
  }
  return out;
}

/**
 * Every upload in `command`, checked: the first whose destination is not
 * sanctioned (as a reason), and the ones that were (as facts the model can be
 * told, since it cannot resolve a remote name to a URL itself).
 */
export function checkUploads(command: string, ctx: UploadContext): UploadCheck {
  const ok: string[] = [];
  for (const walked of walkSegments(command, ctx.cwd)) {
    const { cwd, vars } = walked;
    // Switch on the command that actually runs: `env curl`, `timeout 5 curl`,
    // `xargs curl`, `/usr/bin/curl` and `\curl` all send what curl sends.
    const seg = unwrapSegment(walked.seg);
    let findings: Finding[] = [];
    switch (seg.verb) {
      case "curl":
        findings = curlFinding(seg);
        break;
      case "wget":
        findings = wgetFinding(seg);
        break;
      case "scp":
        findings = copyFinding(seg, "scp");
        break;
      case "rsync":
        findings = copyFinding(seg, "rsync");
        break;
      case "sftp":
        findings = sftpFinding(seg);
        break;
      case "nc":
      case "ncat":
      case "netcat":
        findings = netcatFinding(seg, ctx.line ?? command);
        break;
      case "socat":
        findings = socatFinding(seg);
        break;
      case "git": {
        const g = gitFinding(seg, ctx, cwd, vars);
        findings = g.findings;
        break;
      }
      case "gh":
        findings = ghFinding(seg, ctx, cwd);
        break;
    }
    for (const f of findings) {
      const d = f.d;
      if (d === "local") {
        ok.push(`${f.what} a path on this machine`);
        continue;
      }
      if (d && d.host !== "gist.github.com" && isSanctioned(d, ctx.sanctioned)) {
        ok.push(`${f.what} ${describe(d)}`);
        continue;
      }
      return { unsanctioned: `Upload to an unsanctioned destination: ${f.what} ${f.dest}, which is not loopback and not in sanctionedRemotes`, sanctioned: ok };
    }
  }
  return { unsanctioned: null, sanctioned: ok };
}

/** The first unsanctioned upload in `command` as a reason, or null. */
export function unsanctionedUpload(command: string, ctx: UploadContext): string | null {
  return checkUploads(command, ctx).unsanctioned;
}
