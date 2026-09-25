import { describe, it, expect, afterAll } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseClassificationResponse } from "../src/classifier/client.js";

describe("Classifier Output Parser", () => {
  it("parses clean JSON response", () => {
    const raw = '{"allow": true, "reason": "Safe directory listing"}';
    const parsed = parseClassificationResponse(raw);
    expect(parsed.allow).toBe(true);
    expect(parsed.reason).toBe("Safe directory listing");
  });

  it("parses JSON response wrapped in markdown code fence", () => {
    const raw = '```json\n{"allow": false, "reason": "Destructive deletion"}\n```';
    const parsed = parseClassificationResponse(raw);
    expect(parsed.allow).toBe(false);
    expect(parsed.reason).toBe("Destructive deletion");
  });

  it("extracts JSON surrounded by conversational preamble", () => {
    const raw = 'Here is the security assessment:\n{"allow": true, "reason": "Benign status check"}\nHope this helps!';
    const parsed = parseClassificationResponse(raw);
    expect(parsed.allow).toBe(true);
    expect(parsed.reason).toBe("Benign status check");
  });

  it("fails closed on unparseable garbage", () => {
    const raw = "I cannot determine if this is safe.";
    const parsed = parseClassificationResponse(raw);
    expect(parsed.allow).toBe(false);
  });
});

describe("Classifier Output Parser: allow must be a boolean", () => {
  it("fails closed when allow is missing or not boolean", () => {
    expect(parseClassificationResponse('{"reason": "no verdict"}').allow).toBe(false);
    expect(parseClassificationResponse('{"allow": "true"}').allow).toBe(false);
    expect(parseClassificationResponse('{"allow": 1}').allow).toBe(false);
  });
});

import { LlmClient, requestExtras, markSession } from "../src/classifier/client.js";

describe("LlmClient request composition", () => {
  const capture = () => {
    const bodies: any[] = [];
    const fetchImpl = async (_url: string, init: any) => {
      bodies.push(JSON.parse(init.body));
      return { ok: true, status: 200, text: async () => "", json: async () => ({ choices: [{ message: { content: '{"allow": true, "reason": "ok"}' } }] }) };
    };
    return { bodies, fetchImpl };
  };

  it("switches hidden reasoning off per route, and caps the reply", async () => {
    const { bodies, fetchImpl } = capture();
    await new LlmClient({ baseUrl: "http://x/v1", model: "openrouter/deepseek/deepseek-v4.1-flash" }, fetchImpl).classify("ls");
    await new LlmClient({ baseUrl: "http://x/v1", model: "deepseek/deepseek-flash" }, fetchImpl).classify("ls");
    await new LlmClient({ baseUrl: "http://x/v1", model: "ollama-cloud/gemma4:31b" }, fetchImpl).classify("ls");
    expect(bodies[0].reasoning).toEqual({ enabled: false });
    expect(bodies[1].thinking).toEqual({ type: "disabled" });
    expect(bodies[2].reasoning_effort).toBe("none");
    expect(bodies[0].max_tokens).toBe(120);
    expect(bodies[0].stream).toBe(false);
  });

  it("extraBody overrides and can remove a route default", () => {
    expect(requestExtras("openrouter/x/y", { reasoning: null, top_p: 0.1 })).toEqual({ top_p: 0.1 });
    expect(requestExtras("unknown-route/x", { a: 1 })).toEqual({ a: 1 });
    expect(requestExtras("no-slash")).toEqual({});
  });

  it("asks the triage model first and only escalates its denials", async () => {
    const asked: string[] = [];
    const fetchImpl = async (_url: string, init: any) => {
      const body = JSON.parse(init.body);
      asked.push(body.model);
      const allow = body.model === "big";
      return { ok: true, status: 200, text: async () => "", json: async () => ({ choices: [{ message: { content: JSON.stringify({ allow, reason: body.model }) } }] }) };
    };
    const client = new LlmClient({ baseUrl: "http://x/v1", model: "big", triageModel: "small" }, fetchImpl);
    const r = await client.classify("something");
    expect(asked).toEqual(["small", "big"]);
    expect(r.allow).toBe(true);
    expect(r.source).toBe("llm");
  });
});

describe("LlmClient session attribution", () => {
  const captureHeaders = () => {
    const seen: Array<Record<string, string>> = [];
    const fetchImpl = async (_url: string, init: any) => {
      seen.push(init.headers);
      return { ok: true, status: 200, text: async () => "", json: async () => ({ choices: [{ message: { content: '{"allow": true, "reason": "ok"}' } }] }) };
    };
    return { seen, fetchImpl };
  };

  it("marks the session so gate spend groups with it but does not count as it", async () => {
    const { seen, fetchImpl } = captureHeaders();
    await new LlmClient({ baseUrl: "http://x/v1", model: "deepseek/deepseek-flash" }, fetchImpl)
      .classify("ls", undefined, "ses_abc");
    expect(seen[0]["X-Session-Id"]).toBe("ses_abc:auto-classifier");
    expect(markSession("ses_abc")).toBe("ses_abc:auto-classifier");
    // The prefix is what makes the two questions both answerable.
    expect(seen[0]["X-Session-Id"].startsWith("ses_abc")).toBe(true);
    expect(seen[0]["X-Session-Id"]).not.toBe("ses_abc");
  });

  it("sends no session header when there is no session to name", async () => {
    const { seen, fetchImpl } = captureHeaders();
    await new LlmClient({ baseUrl: "http://x/v1", model: "deepseek/deepseek-flash" }, fetchImpl).classify("ls");
    expect(seen[0]["X-Session-Id"]).toBeUndefined();
  });

  it("marks the triage and fallback calls too, not only the primary", async () => {
    const seen: Array<{ model: string; session?: string }> = [];
    const fetchImpl = async (_url: string, init: any) => {
      const model = JSON.parse(init.body).model;
      seen.push({ model, session: init.headers["X-Session-Id"] });
      if (model !== "deepseek/fallback") throw new Error("upstream down");
      return { ok: true, status: 200, text: async () => "", json: async () => ({ choices: [{ message: { content: '{"allow": true, "reason": "ok"}' } }] }) };
    };
    await new LlmClient(
      { baseUrl: "http://x/v1", model: "deepseek/primary", fallbackModel: "deepseek/fallback", triageModel: "deepseek/triage" },
      fetchImpl,
    ).classify("ls", undefined, "ses_abc");
    expect(seen.length).toBe(3);
    for (const call of seen) expect(call.session).toBe("ses_abc:auto-classifier");
  });
});

describe("LlmClient usage", () => {
  it("sums the tokens every model call behind one classification spent", async () => {
    const { LlmClient } = await import("../src/classifier/client.js");
    let n = 0;
    const fetchImpl = async () => {
      n++;
      if (n === 1) return { ok: false, status: 503, text: async () => "down", json: async () => ({}) };
      return {
        ok: true,
        status: 200,
        text: async () => "",
        json: async () => ({ choices: [{ message: { content: '{"allow": true, "reason": "ok"}' } }], usage: { prompt_tokens: 500, completion_tokens: 12 } }),
      };
    };
    const client = new LlmClient({ baseUrl: "http://x/v1", model: "a", fallbackModel: "b" }, fetchImpl);
    const r = await client.classify("ls");
    expect(r.source).toBe("fallback");
    // The failed primary counts no tokens and no call; the fallback's are reported.
    expect(r.usage).toEqual({ input_tokens: 500, output_tokens: 12, calls: 1 });
  });
});

describe("reasoning-off fields follow the endpoint", () => {
  it("uses the host when the model id has no route prefix", async () => {
    const { requestExtras } = await import("../src/classifier/client.js");
    expect(requestExtras("deepseek/deepseek-v4.1-flash", undefined, "https://openrouter.ai/api/v1")).toEqual({ reasoning: { enabled: false } });
    expect(requestExtras("deepseek-flash", undefined, "https://api.deepseek.com/v1")).toEqual({ thinking: { type: "disabled" } });
    expect(requestExtras("openrouter/x/y", undefined, "http://127.0.0.1:9000/v1")).toEqual({ reasoning: { enabled: false } });
  });
});

describe("LlmClient fallback chain (fallbackModel + fallbackModels)", () => {
  // Each test points AUTO_CLASSIFIER_LOG at its own scratch file so the
  // per-link "also failed" / "retrying with" lines can be asserted on
  // without one test's log bleeding into another's.
  const logDir = fs.mkdtempSync(path.join(os.tmpdir(), "auto-classifier-fallback-log-"));
  afterAll(() => fs.rmSync(logDir, { recursive: true, force: true }));

  function withLog<T>(fn: () => Promise<T>): Promise<T> & { logPath: string } {
    const logPath = path.join(logDir, `log-${Math.random().toString(36).slice(2)}.log`);
    const prev = process.env.AUTO_CLASSIFIER_LOG;
    process.env.AUTO_CLASSIFIER_LOG = logPath;
    const p = fn().finally(() => {
      if (prev === undefined) delete process.env.AUTO_CLASSIFIER_LOG;
      else process.env.AUTO_CLASSIFIER_LOG = prev;
    }) as Promise<T> & { logPath: string };
    p.logPath = logPath;
    return p;
  }

  function readLog(logPath: string): string {
    return fs.existsSync(logPath) ? fs.readFileSync(logPath, "utf-8") : "";
  }

  // Every case below fails the primary model outright, so `classify()`
  // always enters the fallback loop; only the fallback chain's own shape
  // varies per test.
  function failingPrimary(behaviors: Record<string, "fail" | "allow" | "deny" | "garbage">) {
    const asked: string[] = [];
    const fetchImpl = async (_url: string, init: any) => {
      const model = JSON.parse(init.body).model;
      asked.push(model);
      const behavior = behaviors[model] ?? "fail";
      if (behavior === "fail") throw new Error(`${model} unreachable`);
      const content = behavior === "garbage" ? `${model} thinks this looks fine` : JSON.stringify({ allow: behavior === "allow", reason: model });
      return {
        ok: true,
        status: 200,
        text: async () => "",
        json: async () => ({ choices: [{ message: { content } }] }),
      };
    };
    return { asked, fetchImpl };
  }

  it("tries fallbackModel first, then fallbackModels in order", async () => {
    const { asked, fetchImpl } = failingPrimary({ "tier-2": "allow" });
    const client = new LlmClient(
      { baseUrl: "http://x/v1", model: "primary", fallbackModel: "tier-1", fallbackModels: ["tier-2", "tier-3"] },
      fetchImpl,
    );
    const r = await withLog(() => client.classify("ls"));
    expect(asked).toEqual(["primary", "tier-1", "tier-2"]);
    expect(r.allow).toBe(true);
    expect(r.source).toBe("fallback");
  });

  it("skips the primary model and a duplicate if either reappears in fallbackModels", async () => {
    const { asked, fetchImpl } = failingPrimary({ "tier-1": "allow" });
    const client = new LlmClient(
      // "primary" and "tier-1" (already fallbackModel) both reappear here and must be skipped.
      { baseUrl: "http://x/v1", model: "primary", fallbackModel: "tier-1", fallbackModels: ["primary", "tier-1", "tier-1"] },
      fetchImpl,
    );
    const r = await withLog(() => client.classify("ls"));
    expect(asked).toEqual(["primary", "tier-1"]);
    expect(r.source).toBe("fallback");
  });

  it("logs every failed link before moving to the next", async () => {
    const { fetchImpl } = failingPrimary({ "tier-3": "allow" });
    const client = new LlmClient(
      { baseUrl: "http://x/v1", model: "primary", fallbackModel: "tier-1", fallbackModels: ["tier-2", "tier-3"] },
      fetchImpl,
    );
    const call = withLog(() => client.classify("ls"));
    await call;
    const log = readLog(call.logPath);
    expect(log).toContain("primary model (primary) failed");
    expect(log).toContain("retrying with fallback model (tier-1)");
    expect(log).toContain("fallback model (tier-1) also failed");
    expect(log).toContain("retrying with fallback model (tier-2)");
    expect(log).toContain("fallback model (tier-2) also failed");
    expect(log).toContain("retrying with fallback model (tier-3)");
    expect(log).not.toContain("fallback model (tier-3) also failed");
  });

  it("the first link to answer wins and nothing further down the chain is asked", async () => {
    const { asked, fetchImpl } = failingPrimary({ "tier-1": "deny" });
    const client = new LlmClient(
      { baseUrl: "http://x/v1", model: "primary", fallbackModel: "tier-1", fallbackModels: ["tier-2"] },
      fetchImpl,
    );
    const r = await withLog(() => client.classify("ls"));
    expect(asked).toEqual(["primary", "tier-1"]);
    expect(r.allow).toBe(false);
    expect(r.source).toBe("fallback");
  });

  it("fails closed with source error once the whole chain is exhausted", async () => {
    const { asked, fetchImpl } = failingPrimary({});
    const client = new LlmClient(
      { baseUrl: "http://x/v1", model: "primary", fallbackModel: "tier-1", fallbackModels: ["tier-2", "tier-3"] },
      fetchImpl,
    );
    const call = withLog(() => client.classify("ls"));
    const r = await call;
    expect(asked).toEqual(["primary", "tier-1", "tier-2", "tier-3"]);
    expect(r.allow).toBe(false);
    expect(r.source).toBe("error");
    expect(r.reason).toContain("LLM classification unreachable");
    const log = readLog(call.logPath);
    expect(log).toContain("fallback model (tier-3) also failed");
  });

  // "The first reply that parses wins": an unparseable reply is a failed
  // link, not a verdict, so the chain moves on past it.
  it("an unparseable primary reply moves to the fallback chain, and the first reply that parses wins", async () => {
    const { asked, fetchImpl } = failingPrimary({ primary: "garbage", "tier-1": "garbage", "tier-2": "allow" });
    const client = new LlmClient(
      { baseUrl: "http://x/v1", model: "primary", fallbackModel: "tier-1", fallbackModels: ["tier-2", "tier-3"] },
      fetchImpl,
    );
    const call = withLog(() => client.classify("ls"));
    const r = await call;
    expect(asked).toEqual(["primary", "tier-1", "tier-2"]);
    expect(r.allow).toBe(true);
    expect(r.source).toBe("fallback");
    expect(r.usage?.calls).toBe(3);
    const log = readLog(call.logPath);
    expect(log).toContain("primary model (primary) failed: unparseable reply");
    expect(log).toContain("fallback model (tier-1) also failed: unparseable reply");
  });

  it("an unparseable primary with no fallback configured is still a fail-closed deny", async () => {
    const { asked, fetchImpl } = failingPrimary({ primary: "garbage" });
    const client = new LlmClient({ baseUrl: "http://x/v1", model: "primary" }, fetchImpl);
    const r = await withLog(() => client.classify("ls"));
    expect(asked).toEqual(["primary"]);
    expect(r.allow).toBe(false);
    expect(r.reason).toContain("Failed to parse classifier JSON output");
  });

  it("a chain exhausted with any unparseable reply denies as a verdict (source llm), not as an outage", async () => {
    // A model that answered, just not parseably, is not an outage: the retry
    // reuses this denial rather than re-asking until a reply happens to parse.
    const { asked, fetchImpl } = failingPrimary({ primary: "garbage", "tier-1": "fail" });
    const client = new LlmClient({ baseUrl: "http://x/v1", model: "primary", fallbackModel: "tier-1" }, fetchImpl);
    const r = await withLog(() => client.classify("ls"));
    expect(asked).toEqual(["primary", "tier-1"]);
    expect(r.allow).toBe(false);
    expect(r.source).toBe("llm");
    expect(r.reason).toContain("Failed to parse classifier JSON output");
  });

  it("an unparseable triage reply still goes to the primary, and an unparseable primary then to the fallback", async () => {
    const { asked, fetchImpl } = failingPrimary({ triage: "garbage", primary: "garbage", "tier-1": "deny" });
    const client = new LlmClient(
      { baseUrl: "http://x/v1", model: "primary", triageModel: "triage", fallbackModel: "tier-1" },
      fetchImpl,
    );
    const r = await withLog(() => client.classify("ls"));
    expect(asked).toEqual(["triage", "primary", "tier-1"]);
    expect(r.allow).toBe(false);
    expect(r.source).toBe("fallback");
    expect(r.reason).toBe("tier-1");
  });

  it("with no fallbackModel set, fallbackModels alone still forms the chain", async () => {
    const { asked, fetchImpl } = failingPrimary({ "only-fallback": "allow" });
    const client = new LlmClient(
      { baseUrl: "http://x/v1", model: "primary", fallbackModels: ["only-fallback"] },
      fetchImpl,
    );
    const r = await withLog(() => client.classify("ls"));
    expect(asked).toEqual(["primary", "only-fallback"]);
    expect(r.source).toBe("fallback");
  });
});

describe("LlmClient: the whole chain has one deadline", () => {
  /** A fetch that never answers, only honours its abort signal, and counts the models asked. */
  const hanging = () => {
    const asked: string[] = [];
    const fetchImpl = (_url: string, init: any) =>
      new Promise<any>((_resolve, reject) => {
        asked.push(JSON.parse(init.body).model);
        init.signal.addEventListener("abort", () => reject(new Error("aborted")));
      });
    return { asked, fetchImpl };
  };

  it("fails closed as a transient error once llm.totalTimeoutMs has passed, however many links are left", async () => {
    const { asked, fetchImpl } = hanging();
    const client = new LlmClient(
      { baseUrl: "http://127.0.0.1:9/v1", model: "a", fallbackModel: "b", fallbackModels: ["c", "d"], triageModel: "t", timeoutMs: 400, totalTimeoutMs: 600 },
      fetchImpl as any
    );
    const started = Date.now();
    const out = await client.classify("echo hi");
    const took = Date.now() - started;
    expect(out.allow).toBe(false);
    expect(out.source).toBe("error");
    expect(out.reason).toContain("totalTimeoutMs");
    expect(took).toBeLessThan(900);
    expect(asked.length).toBeLessThan(5);
  });

  it("gives a link only the time the deadline has left", async () => {
    const { fetchImpl } = hanging();
    const client = new LlmClient({ baseUrl: "http://127.0.0.1:9/v1", model: "a", timeoutMs: 5000, totalTimeoutMs: 300 }, fetchImpl as any);
    const started = Date.now();
    await client.classify("echo hi");
    expect(Date.now() - started).toBeLessThan(800);
  });
});
