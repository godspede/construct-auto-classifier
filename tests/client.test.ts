import { describe, it, expect } from "bun:test";
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
