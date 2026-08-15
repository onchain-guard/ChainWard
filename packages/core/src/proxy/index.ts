// ChainWard LLM proxy — the guard for harnesses whose code you do not own.
//
// The library form (`guard()`) needs you to hold the code that calls the model. When you
// don't — Claude Code, a vendor agent, a binary — there is still one thing you can change:
// where the requests go. This process sits at that address, sanitizes the untrusted parts
// of every request, and forwards the rest untouched.
//
//   chainward-proxy --upstream https://api.anthropic.com
//   export ANTHROPIC_BASE_URL=http://localhost:8787
//
// Zero runtime dependencies beyond chainward itself (node:http + fetch).

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { guard, type ChatMessage } from "../index.ts";

export interface GuardEvent {
  /** epoch ms */
  t: number;
  model: string;
  /** true when the request asked for a streamed response */
  stream: boolean;
  findings: Array<{
    index: number;
    role: string;
    severity: string;
    codes: string[];
    /** first 200 chars of the message as it arrived */
    before: string;
    /** first 200 chars of what the model actually received */
    after: string;
  }>;
}

export interface ProxyOptions {
  /** port the guarded LLM endpoint listens on (default 8787) */
  port?: number;
  /** real API base to forward to, e.g. https://api.anthropic.com. Omitted → dry-run */
  upstream?: string;
  /** port for the read-only event API (default 8788). Omitted → not started */
  eventPort?: number;
  /** how many recent events to keep for late subscribers (default 100) */
  bufferSize?: number;
  /** called for every request, guarded or not */
  onEvent?: (e: GuardEvent) => void;
}

/** Request paths we treat as an LLM call. Both vendor shapes carry `messages`. */
const LLM_PATHS = ["/chat/completions", "/messages", "/responses"];

/** Headers worth forwarding upstream. An allow-list, because blindly copying `host` or
 *  `content-length` produces requests the upstream rejects. */
const FORWARD_HEADERS = [
  "authorization",
  "x-api-key",
  "anthropic-version",
  "anthropic-beta",
  "openai-organization",
  "openai-beta",
];

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => resolve(b));
    req.on("error", reject);
  });
}

/** A readable preview of message content, which is a plain string in the OpenAI shape and
 *  an array of typed blocks in the Anthropic one. Flattening the block case matters: the
 *  injection lives in `tool_result`, so a preview that only understood strings would show
 *  an empty line for exactly the messages worth looking at. */
export function preview(content: unknown, limit = 200): string {
  if (typeof content === "string") return content.slice(0, limit);
  if (!Array.isArray(content)) return "";
  const parts: string[] = [];
  for (const b of content as Array<Record<string, unknown>>) {
    if (b?.type === "text" && typeof b.text === "string") parts.push(b.text);
    else if (b?.type === "tool_result") {
      if (typeof b.content === "string") parts.push(b.content);
      else if (Array.isArray(b.content)) {
        for (const c of b.content as Array<Record<string, unknown>>) {
          if (c?.type === "text" && typeof c.text === "string") parts.push(c.text);
        }
      }
    }
  }
  return parts.join(" ⏎ ").slice(0, limit);
}

/** Forward the sanitized request. Streamed responses are piped rather than buffered:
 *  `await res.text()` would hold the whole completion and only then release it, which
 *  turns a streaming client into a client that appears to hang for the whole generation. */
async function forward(
  req: IncomingMessage,
  res: ServerResponse,
  upstream: string,
  body: unknown,
  rawBody?: string,
): Promise<void> {
  const url = upstream.replace(/\/$/, "") + (req.url ?? "");
  const headers: Record<string, string> = {};
  if (body !== undefined || rawBody) headers["content-type"] = "application/json";
  for (const h of FORWARD_HEADERS) {
    const v = req.headers[h];
    if (typeof v === "string") headers[h] = v;
  }

  const method = req.method ?? "GET";
  const payload =
    method === "GET" || method === "HEAD"
      ? undefined
      : body !== undefined
        ? JSON.stringify(body)
        : rawBody;

  let up: Response;
  try {
    up = await fetch(url, { method, headers, body: payload });
  } catch (e) {
    res.writeHead(502, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "chainward: upstream request failed", detail: String(e) }));
    return;
  }

  const outHeaders: Record<string, string> = {};
  for (const h of ["content-type", "cache-control"]) {
    const v = up.headers.get(h);
    if (v) outHeaders[h] = v;
  }
  res.writeHead(up.status, outHeaders);

  if (!up.body) {
    res.end(await up.text());
    return;
  }
  // Stream through in both directions so SSE arrives token-by-token as the upstream sends it.
  Readable.fromWeb(up.body as Parameters<typeof Readable.fromWeb>[0]).pipe(res);
}

/** The dry-run reply. Shaped like a completion so a client does not crash, and worded so
 *  nobody mistakes it for a model answer. */
function dryRun(res: ServerResponse, model: string, ev: GuardEvent): void {
  const codes = [...new Set(ev.findings.flatMap((f) => f.codes))];
  const note =
    `[chainward dry-run] guarded ${ev.findings.length} message(s)` +
    (codes.length ? `: ${codes.join(", ")}` : "") +
    `. No upstream configured — pass --upstream to forward to a real model.`;
  res.writeHead(200, { "content-type": "application/json" });
  res.end(
    JSON.stringify({
      id: "chainward-dryrun",
      object: "chat.completion",
      model,
      choices: [{ index: 0, message: { role: "assistant", content: note }, finish_reason: "stop" }],
    }),
  );
}

/**
 * Start the proxy. Returns the servers so a caller (or a test) can close them.
 *
 * The event API is read-only and deliberately UI-free: it serves JSON and SSE so a
 * separate front-end can render however it likes.
 */
export interface Proxy {
  llm: Server;
  events?: Server;
  /** Shut both listeners down and drop live connections.
   *
   *  `Server.close()` alone stops new connections but waits for existing ones, and an SSE
   *  subscriber never ends on its own — so a caller that only called `close()` would hang
   *  for as long as a dashboard stayed open. */
  close(): Promise<void>;
}

export function createProxy(opts: ProxyOptions = {}): Proxy {
  const bufferSize = opts.bufferSize ?? 100;
  const buffer: GuardEvent[] = [];
  const subscribers = new Set<ServerResponse>();

  const publish = (e: GuardEvent) => {
    buffer.push(e);
    while (buffer.length > bufferSize) buffer.shift();
    const frame = `data: ${JSON.stringify(e)}\n\n`;
    for (const s of subscribers) s.write(frame);
    opts.onEvent?.(e);
  };

  const llm = createServer(async (req, res) => {
    const isLLMCall = req.method === "POST" && LLM_PATHS.some((p) => req.url?.includes(p));

    if (!isLLMCall) {
      // A client pointed at this proxy sends it EVERYTHING, not just completions — token
      // counts, model lists, org lookups. Refusing those would break the very setup this
      // is for (`ANTHROPIC_BASE_URL=…` in front of an agent you don't control), so relay
      // them untouched. There is nothing to guard in them: the payload rides in messages.
      if (opts.upstream) {
        await forward(req, res, opts.upstream, undefined, await readBody(req));
      } else {
        res.writeHead(404, {
          "content-type": "application/json",
        });
        res.end(
          JSON.stringify({
            error: "chainward: no upstream configured, so only LLM endpoints are handled",
            path: req.url,
            hint: "pass --upstream to relay everything else through to the real API",
          }),
        );
      }
      return;
    }

    let body: Record<string, unknown>;
    try {
      body = JSON.parse(await readBody(req));
    } catch {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "chainward: request body is not valid JSON" }));
      return;
    }

    const model = typeof body.model === "string" ? body.model : "unknown";
    const stream = body.stream === true;
    const messages = Array.isArray(body.messages) ? (body.messages as ChatMessage[]) : [];
    // Snapshot before guarding — `guard()` returns new objects, but the previews have to
    // show what actually arrived, not what we are about to send.
    const originals = messages.map((m) => preview(m.content));

    let event: GuardEvent = { t: Date.now(), model, stream, findings: [] };
    if (messages.length) {
      try {
        const { messages: cleaned, findings } = await guard(messages, {
          model,
          targetContext: ["llm-chat", "markdown-ui"],
        });
        body.messages = cleaned;
        event = {
          t: Date.now(),
          model,
          stream,
          findings: findings.map((f) => ({
            index: f.index,
            role: f.role,
            severity: f.severity,
            codes: f.codes,
            before: originals[f.index] ?? "",
            after: preview(cleaned[f.index]?.content),
          })),
        };
      } catch (e) {
        // A guard that takes the caller's agent offline is a worse failure than one that
        // misses. Forward the original and make the miss visible instead of silent.
        event = {
          t: Date.now(),
          model,
          stream,
          findings: [
            { index: -1, role: "system", severity: "ERROR", codes: ["GUARD_FAILED"], before: String(e), after: "" },
          ],
        };
      }
    }
    publish(event);

    if (opts.upstream) await forward(req, res, opts.upstream, body);
    else dryRun(res, model, event);
  });
  llm.listen(opts.port ?? 8787);

  const shutdown = (servers: Server[]) => async (): Promise<void> => {
    for (const s of subscribers) s.end();
    subscribers.clear();
    await Promise.all(
      servers.map(
        (s) =>
          new Promise<void>((resolve) => {
            s.closeAllConnections();
            s.close(() => resolve());
          }),
      ),
    );
  };

  if (opts.eventPort === undefined) return { llm, close: shutdown([llm]) };

  const events = createServer((req, res) => {
    // A front-end served from another origin (a dev server, say) has to be able to read this.
    const cors = { "access-control-allow-origin": "*" };

    if (req.url === "/events") {
      res.writeHead(200, {
        ...cors,
        "content-type": "text/event-stream",
        "cache-control": "no-cache",
        connection: "keep-alive",
      });
      // Replay the buffer so a client that connects mid-session is not staring at nothing.
      for (const e of buffer) res.write(`data: ${JSON.stringify(e)}\n\n`);
      subscribers.add(res);
      req.on("close", () => subscribers.delete(res));
      return;
    }

    if (req.url === "/events/recent") {
      res.writeHead(200, { ...cors, "content-type": "application/json" });
      res.end(JSON.stringify(buffer));
      return;
    }

    if (req.url === "/health") {
      res.writeHead(200, { ...cors, "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, buffered: buffer.length, subscribers: subscribers.size }));
      return;
    }

    res.writeHead(404, { ...cors, "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found", routes: ["/events", "/events/recent", "/health"] }));
  });
  events.listen(opts.eventPort);

  return { llm, events, close: shutdown([llm, events]) };
}
