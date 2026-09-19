import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { analyzeCommand } from "../rules/command-shape.js";

export interface DenialRecord {
  /** The command exactly as last attempted. */
  command: string;
  /** The key denials are counted under; see normalizeCommand. */
  normalizedCommand: string;
  reason: string;
  /** When this command was last denied. */
  timestamp: number;
  /** Denials of this command inside the sliding window. */
  count: number;
  /** The denial came from an unreachable or unparseable model, not a verdict. */
  transient?: boolean;
}

export interface AllowRecord {
  /** normalizeCommand() of the command, plus a content hash when a file was judged with it. */
  key: string;
  reason: string;
  timestamp: number;
}

export interface SessionStateData {
  conversationId: string;
  totalDenials: number;
  /** One record per distinct command, most recent last; capped at 20. */
  recentDenials: DenialRecord[];
  /** Model allows inside the window, so the same command is not re-asked; capped at 50. */
  recentAllows: AllowRecord[];
  createdAt: number;
  updatedAt: number;
}

export interface DenialTally {
  /** Denials of this command inside the window, including this one. */
  consecutiveCount: number;
  /** The count reached the threshold: hand the command to the operator. */
  escalated: boolean;
}

/** Verbs that only shape output; a trailing pipe into one does not change what a command does. */
const OUTPUT_SHAPERS = new Set(["head", "tail", "cat", "less", "more", "wc", "tee"]);

/**
 * Tracks, per session, how many times each command has been denied inside a
 * sliding window. The counter is keyed on the command, not the session: an
 * agent that is denied, does unrelated allowed work, and retries has retried,
 * and the count must say so. Only an allowed run of the *same* command, or the
 * window lapsing, clears it.
 */
export class StateManager {
  private baseDir: string;
  private slidingWindowMs: number;
  private consecutiveThreshold: number;
  private now: () => number;

  /**
   * @param baseDir where session files live; omitted, it resolves to
   *   $XDG_RUNTIME_DIR/auto-classifier/sessions or ~/.cache/auto-classifier/sessions.
   *   Tests pass a temp dir so they never touch the box's real store.
   * @param now clock seam for tests.
   */
  constructor(slidingWindowMs = 300000, consecutiveThreshold = 3, baseDir?: string, now: () => number = Date.now) {
    this.slidingWindowMs = slidingWindowMs;
    this.consecutiveThreshold = consecutiveThreshold;
    this.now = now;

    const runtimeDir = process.env.XDG_RUNTIME_DIR;
    if (baseDir) {
      this.baseDir = baseDir;
    } else if (runtimeDir && fs.existsSync(runtimeDir)) {
      this.baseDir = path.join(runtimeDir, "auto-classifier", "sessions");
    } else {
      this.baseDir = path.join(os.homedir(), ".cache", "auto-classifier", "sessions");
    }

    this.ensureDir(this.baseDir);
    this.pruneStaleSessions();
  }

  private ensureDir(dir: string): void {
    if (!fs.existsSync(dir)) {
      try {
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      } catch (err) {
        console.error(`[auto-classifier] Failed to create state dir ${dir}:`, err);
      }
    }
  }

  private getSessionFilePath(sessionId: string): string {
    const safeId = crypto.createHash("sha256").update(sessionId).digest("hex").slice(0, 32);
    return path.join(this.baseDir, `${safeId}.json`);
  }

  /**
   * The key a command's denials are counted under. Two attempts that differ
   * only in a privilege prefix, whitespace, an fd redirection, or a trailing
   * `| tail -15` are the same attempt: the agent is retrying, not trying
   * something else.
   */
  normalizeCommand(cmd: string): string {
    const shape = analyzeCommand(cmd);
    const parts = shape.segments.map((seg) =>
      seg.stripped
        .replace(/\s+\d*>&\d+/g, "")
        .replace(/\s+/g, " ")
        .trim()
    );
    while (parts.length > 1) {
      const last = shape.segments[parts.length - 1];
      if (OUTPUT_SHAPERS.has(last.verb)) parts.pop();
      else break;
    }
    const key = parts.join(" ; ");
    // The splitter stops at a here-document, so its body is in no segment; two
    // different heredoc scripts must not share a key (and so a cached verdict).
    const body = shape.hasHeredoc ? ` #heredoc:${crypto.createHash("sha1").update(cmd.slice(cmd.indexOf("<<"))).digest("hex").slice(0, 16)}` : "";
    return (key || cmd.trim().replace(/\s+/g, " ")) + body;
  }

  private emptySession(sessionId: string): SessionStateData {
    const now = this.now();
    return { conversationId: sessionId, totalDenials: 0, recentDenials: [], recentAllows: [], createdAt: now, updatedAt: now };
  }

  loadSession(sessionId: string): SessionStateData {
    const filePath = this.getSessionFilePath(sessionId);
    if (!fs.existsSync(filePath)) {
      return this.emptySession(sessionId);
    }

    try {
      const raw = fs.readFileSync(filePath, "utf-8");
      const data = JSON.parse(raw) as Partial<SessionStateData>;
      if (!Array.isArray(data.recentDenials)) {
        // A file written by an older layout: start clean rather than misread it.
        return this.emptySession(sessionId);
      }
      return {
        ...this.emptySession(sessionId),
        ...data,
        recentDenials: data.recentDenials.filter((r) => typeof r?.count === "number"),
        recentAllows: Array.isArray(data.recentAllows) ? data.recentAllows : [],
      };
    } catch {
      return this.emptySession(sessionId);
    }
  }

  saveSession(state: SessionStateData): void {
    const filePath = this.getSessionFilePath(state.conversationId);
    state.updatedAt = this.now();

    const tmpPath = `${filePath}.${process.pid}.${Math.random().toString(36).slice(2)}.tmp`;
    try {
      fs.writeFileSync(tmpPath, JSON.stringify(state, null, 2), { mode: 0o600 });
      fs.renameSync(tmpPath, filePath);
    } catch (err) {
      console.error(`[auto-classifier] Failed to save session state for ${state.conversationId}:`, err);
      try {
        if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
      } catch {}
    }
  }

  private liveRecord(state: SessionStateData, normalized: string): DenialRecord | undefined {
    const rec = state.recentDenials.find((r) => r.normalizedCommand === normalized);
    if (!rec) return undefined;
    return this.now() - rec.timestamp <= this.slidingWindowMs ? rec : undefined;
  }

  /**
   * A denial of this command still inside the window, if any. A retry of a
   * denied command does not need the model again: the verdict is known, and
   * what the retry is for is the count toward operator review.
   */
  recentDenial(sessionId: string, command: string): DenialRecord | undefined {
    return this.liveRecord(this.loadSession(sessionId), this.normalizeCommand(command));
  }

  recordDenial(sessionId: string, command: string, reason: string, opts: { transient?: boolean } = {}): DenialTally {
    const state = this.loadSession(sessionId);
    const now = this.now();
    const normalized = this.normalizeCommand(command);

    const live = this.liveRecord(state, normalized);
    state.recentDenials = state.recentDenials.filter((r) => r.normalizedCommand !== normalized);
    const record: DenialRecord = {
      command,
      normalizedCommand: normalized,
      reason,
      timestamp: now,
      count: (live?.count ?? 0) + 1,
      transient: opts.transient || undefined,
    };
    state.recentDenials.push(record);
    state.totalDenials++;

    if (state.recentDenials.length > 20) {
      state.recentDenials.shift();
    }

    this.saveSession(state);
    return { consecutiveCount: record.count, escalated: record.count >= this.consecutiveThreshold };
  }

  private allowKey(command: string, contextKey?: string): string {
    const base = this.normalizeCommand(command);
    return contextKey ? `${base}#${contextKey}` : base;
  }

  /**
   * A model allow of this command (and, when a file was judged with it, the
   * same file content) still inside the window. The model only sees the text
   * it is shown, so the same text gets the same answer; asking again buys
   * nothing but tokens.
   */
  recentAllow(sessionId: string, command: string, contextKey?: string): AllowRecord | undefined {
    const key = this.allowKey(command, contextKey);
    const rec = this.loadSession(sessionId).recentAllows.find((r) => r.key === key);
    return rec && this.now() - rec.timestamp <= this.slidingWindowMs ? rec : undefined;
  }

  /**
   * @param opts.exploratory the command was structurally read-only (a fast-allow).
   *   Those never touch the counters: an agent must not be able to interleave
   *   `ls` between retries and change what the next retry means.
   * @param opts.reason the model's reason; recorded so a repeat inside the window skips the model.
   * @param opts.contextKey hash of any file content the verdict depended on.
   */
  recordAllow(sessionId: string, command: string, opts: { exploratory?: boolean; reason?: string; contextKey?: string } = {}): void {
    if (opts.exploratory) {
      return;
    }
    const state = this.loadSession(sessionId);
    const normalized = this.normalizeCommand(command);
    state.recentDenials = state.recentDenials.filter((r) => r.normalizedCommand !== normalized);
    if (opts.reason !== undefined) {
      const key = this.allowKey(command, opts.contextKey);
      state.recentAllows = state.recentAllows.filter((r) => r.key !== key);
      state.recentAllows.push({ key, reason: opts.reason, timestamp: this.now() });
      if (state.recentAllows.length > 50) state.recentAllows.shift();
    }
    this.saveSession(state);
  }

  pruneStaleSessions(maxAgeMs = 7200000): void {
    // Prune files older than 2 hours
    try {
      if (!fs.existsSync(this.baseDir)) return;
      const files = fs.readdirSync(this.baseDir);
      const now = Date.now();
      for (const file of files) {
        if (!file.endsWith(".json")) continue;
        const fullPath = path.join(this.baseDir, file);
        try {
          const stat = fs.statSync(fullPath);
          if (now - stat.mtimeMs > maxAgeMs) {
            fs.unlinkSync(fullPath);
          }
        } catch {}
      }
    } catch {}
  }
}
