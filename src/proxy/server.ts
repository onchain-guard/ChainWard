// ChainWard LLM proxy — the drop-in guard for harnesses you don't control (Claude Code etc.).
//
//   npx chainward proxy --inspect            # dry-run + web inspector at :8788
//   UPSTREAM=https://api.openai.com npx chainward proxy   # forward to a real LLM
//   export OPENAI_API_BASE=http://localhost:8787/v1       # point your agent here
//
// It speaks the OpenAI (/v1/chat/completions) and Anthropic (/v1/messages) request shapes,
// runs guard() over the untrusted messages BEFORE forwarding, and (with --inspect) streams
// every interception to a local web UI. Zero runtime deps (node:http).

import { createServer } from "node:http";
import { guard } from "../index.ts";
import type { ChatMessage } from "../index.ts";

interface Opts { port: number; inspectPort: number; inspect: boolean; upstream?: string; model?: string; }

function parseArgs(argv: string[]): Opts {
  const o: Opts = { port: 8787, inspectPort: 8788, inspect: false, upstream: process.env.UPSTREAM };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--port") o.port = Number(argv[++i]);
    else if (argv[i] === "--inspect-port") o.inspectPort = Number(argv[++i]);
    else if (argv[i] === "--inspect") o.inspect = true;
    else if (argv[i] === "--upstream") o.upstream = argv[++i];
  }
  return o;
}

// ---- inspector event bus (SSE) ----
interface Event { t: number; model: string; findings: number; details: Array<{ role: string; severity: string; codes: string[]; before: string; after: string }>; }
const events: Event[] = [];
const sseClients = new Set<import("node:http").ServerResponse>();
function emit(e: Event) {
  events.push(e); if (events.length > 100) events.shift();
  const data = `data: ${JSON.stringify(e)}\n\n`;
  for (const c of sseClients) c.write(data);
}

function readBody(req: import("node:http").IncomingMessage): Promise<string> {
  return new Promise((res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => res(b)); });
}

// Extract {role, content} messages from either API shape; return a setter to write back.
function extractMessages(body: any): { msgs: ChatMessage[]; writeBack: (m: ChatMessage[]) => void } {
  if (Array.isArray(body.messages)) {
    return { msgs: body.messages, writeBack: (m) => { body.messages = m; } };
  }
  return { msgs: [], writeBack: () => {} };
}

async function handleLLM(req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse, opts: Opts) {
  const raw = await readBody(req);
  let body: any; try { body = JSON.parse(raw); } catch { res.writeHead(400).end('{"error":"bad json"}'); return; }

  const { msgs, writeBack } = extractMessages(body);
  const model = body.model ?? opts.model ?? "unknown";
  const originals = msgs.map((m) => (typeof m.content === "string" ? m.content : ""));

  const { messages: cleaned, findings } = await guard(msgs as ChatMessage[], {
    model,
    targetContext: ["llm-chat", "markdown-ui"],
  });
  writeBack(cleaned);

  const details = findings.map((f) => ({
    role: f.role, severity: f.severity, codes: f.codes,
    before: originals[f.index].slice(0, 160),
    after: String((cleaned[f.index] as any).content).slice(0, 160),
  }));
  emit({ t: Date.now(), model, findings: details.length, details });

  if (opts.upstream) {
    // forward the SANITIZED body to the real LLM
    const url = opts.upstream.replace(/\/$/, "") + req.url;
    const headers: Record<string, string> = { "content-type": "application/json" };
    for (const h of ["authorization", "x-api-key", "anthropic-version"]) if (req.headers[h]) headers[h] = String(req.headers[h]);
    try {
      const up = await fetch(url, { method: "POST", headers, body: JSON.stringify(body) });
      res.writeHead(up.status, { "content-type": up.headers.get("content-type") ?? "application/json" });
      res.end(await up.text());
    } catch (e) {
      res.writeHead(502).end(JSON.stringify({ error: "upstream failed", detail: String(e) }));
    }
  } else {
    // dry-run: prove the interception without needing a key
    const note = `[chainward dry-run] guarded ${details.length} message(s): ${details.flatMap((d) => d.codes).join(", ") || "none"}. Set --upstream to forward to a real model.`;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({
      id: "chainward-dryrun", object: "chat.completion", model,
      choices: [{ index: 0, message: { role: "assistant", content: note }, finish_reason: "stop" }],
    }));
  }
}

const INSPECTOR_HTML = `<!doctype html><meta charset=utf8><title>ChainWard Inspector</title>
<style>body{font:14px system-ui;margin:0;background:#0d0d0f;color:#e8e8e8}
header{padding:14px 18px;background:#161619;border-bottom:1px solid #2a2a2e}
h1{font-size:16px;margin:0}small{color:#888}
.ev{border-bottom:1px solid #222;padding:12px 18px}
.mal{color:#e07a5f}.susp{color:#e0b15f}.clean{color:#42c98a}
.codes{font-family:ui-monospace,monospace;font-size:12px;color:#e07a5f}
.ba{font-family:ui-monospace,monospace;font-size:12px;white-space:pre-wrap;word-break:break-all;margin:4px 0;padding:6px 8px;background:#161619;border-radius:6px}
.tag{color:#6fa8dc}</style>
<header><h1>🛡 ChainWard Inspector</h1><small>live LLM-proxy interceptions · <span id=n>0</span> events</small></header>
<div id=log></div>
<script>
let n=0;const log=document.getElementById('log');
const es=new EventSource('/events');
es.onmessage=e=>{const d=JSON.parse(e.data);n++;document.getElementById('n').textContent=n;
 const sev=d.findings?'mal':'clean';
 let h='<div class=ev><b class="'+sev+'">'+(d.findings?('⚠ '+d.findings+' flagged'):'✔ clean')+'</b> <span class=tag>model='+d.model+'</span>';
 for(const x of d.details){h+='<div><span class="'+(x.severity==='MALICIOUS'?'mal':'susp')+'">'+x.severity+'</span> ['+x.role+'] <span class=codes>'+x.codes.join(', ')+'</span>'
  +'<div class=ba>before: '+esc(x.before)+'</div><div class=ba>after&nbsp;: '+esc(x.after)+'</div></div>';}
 h+='</div>';log.insertAdjacentHTML('afterbegin',h);};
function esc(s){return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
</script>`;

function main() {
  const opts = parseArgs(process.argv.slice(2));

  createServer(async (req, res) => {
    if (req.method === "POST" && (req.url?.includes("/chat/completions") || req.url?.includes("/messages"))) {
      return handleLLM(req, res, opts);
    }
    res.writeHead(404).end();
  }).listen(opts.port, () => console.error(`chainward proxy on :${opts.port} (${opts.upstream ? "forward → " + opts.upstream : "dry-run"})`));

  if (opts.inspect) {
    createServer((req, res) => {
      if (req.url === "/events") {
        res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
        sseClients.add(res); req.on("close", () => sseClients.delete(res));
        for (const e of events.slice(-20)) res.write(`data: ${JSON.stringify(e)}\n\n`);
      } else {
        res.writeHead(200, { "content-type": "text/html" }); res.end(INSPECTOR_HTML);
      }
    }).listen(opts.inspectPort, () => console.error(`chainward inspector on http://localhost:${opts.inspectPort}`));
  }
}

main();
