# -*- coding: utf-8 -*-
"""
sternuke.webgui
===============

A local, browser-based dashboard for sternuke served on localhost.

Unlike :mod:`sternuke.gui` (a native ``tkinter`` desktop window), this module
runs a small ``aiohttp`` web server so the operator can drive assessments from a
browser at ``http://127.0.0.1:8787`` - which works headless and inside a
container. It reuses the exact :func:`sternuke.cli.run_assessment` and
:func:`sternuke.cli.run_orchestration` loops, streams live log lines over
Server-Sent Events, and renders the findings table.

Scope
-----
The server binds to the loopback interface (``127.0.0.1``) by default so only
the local machine can reach it. Binding to a non-loopback address requires an
explicit ``--host`` and prints a clear warning; there is no authentication, so
never expose this dashboard on an untrusted network.
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    from aiohttp import web
except ImportError as _exc:  # pragma: no cover
    web = None  # type: ignore
    _AIOHTTP_ERR = _exc

from .engine import Finding
from .assets import AssetParser


def _headers_from_text(text: str) -> dict:
    """Parse a textarea of 'Name: value' lines into a headers dict."""
    from .cli import parse_headers
    return parse_headers([text]) if text else {}


def _params_from_text(text: str):
    """Parse 'key=value' lines into a params dict (or None if empty)."""
    out: dict = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if "=" in line:
            key, _, val = line.partition("=")
            out[key.strip()] = val.strip()
    return out or None


# ---------------------------------------------------------------------------
# Job management
# ---------------------------------------------------------------------------
@dataclass
class Job:
    """A single running assessment/orchestration job."""

    kind: str
    status: str = "running"                       # running | done | error
    logs: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    queue: "asyncio.Queue[dict]" = field(default_factory=asyncio.Queue)
    task: Optional[asyncio.Task] = None

    def emit(self, event: dict) -> None:
        self.queue.put_nowait(event)


class JobManager:
    """Runs one job at a time and fans log/finding events out to SSE clients."""

    def __init__(self) -> None:
        self.current: Optional[Job] = None

    def busy(self) -> bool:
        return self.current is not None and self.current.status == "running"

    def _log_sink(self, job: Job):
        def sink(line: str) -> None:
            job.logs.append(line)
            job.emit({"type": "log", "line": line})
        return sink

    async def _finish(self, job: Job, coro) -> None:
        try:
            findings: List[Finding] = await coro
            job.findings = [f.to_dict() for f in findings]
            job.status = "done"
            job.emit({"type": "done", "findings": job.findings,
                      "count": len(job.findings)})
        except Exception as exc:  # noqa: BLE001 - surface to the UI
            job.status = "error"
            job.emit({"type": "error", "message": str(exc)})

    def start(self, kind: str, coro_factory) -> Job:
        """Create a job; ``coro_factory(log_sink)`` returns the coroutine to run."""
        job = Job(kind=kind)
        self.current = job
        coro = coro_factory(self._log_sink(job))
        job.task = asyncio.ensure_future(self._finish(job, coro))
        return job


# ---------------------------------------------------------------------------
# HTML (single page, inline CSS/JS - no external assets)
# ---------------------------------------------------------------------------
_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sternuke dashboard</title>
<style>
:root{--bg:#0f1115;--panel:#161a22;--fg:#d6e2f0;--muted:#8aa0b6;--accent:#4a9eff;
--crit:#b00020;--high:#d1495b;--med:#e08e0b;--low:#2a9d8f;--info:#577590;--line:#232a35}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
header{padding:14px 20px;border-bottom:1px solid var(--line);display:flex;
align-items:center;gap:12px}header h1{font-size:18px;margin:0}
.badge{font-size:11px;color:var(--muted);border:1px solid var(--line);
padding:2px 8px;border-radius:10px}
main{display:grid;grid-template-columns:380px 1fr;gap:16px;padding:16px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
label{display:block;font-size:12px;color:var(--muted);margin:10px 0 4px}
input,select,textarea{width:100%;background:#0b0e13;color:var(--fg);border:1px solid var(--line);
border-radius:6px;padding:8px;font:13px monospace}
textarea{resize:vertical;min-height:90px}
.row{display:flex;gap:8px}.row>*{flex:1}
button{background:var(--accent);color:#06121f;border:0;border-radius:6px;padding:9px 14px;
font-weight:600;cursor:pointer;margin-top:12px}button.secondary{background:#26313f;color:var(--fg)}
button:disabled{opacity:.5;cursor:not-allowed}
.tabs{display:flex;gap:6px;margin-bottom:8px}.tab{padding:6px 12px;border:1px solid var(--line);
border-radius:6px;cursor:pointer;color:var(--muted)}.tab.active{background:#26313f;color:var(--fg)}
.checks label{display:flex;align-items:center;gap:8px;color:var(--fg);margin:6px 0}
.checks input{width:auto}
#log{background:#0a0d12;border:1px solid var(--line);border-radius:8px;height:260px;overflow:auto;
padding:10px;font:12px/1.45 monospace;white-space:pre-wrap;color:#c7d6e6}
table{width:100%;border-collapse:collapse;margin-top:8px}th,td{text-align:left;padding:6px 8px;
border-bottom:1px solid var(--line);font-size:13px;vertical-align:top}
th{color:var(--muted);font-weight:600}
.sev{font-weight:700;font-size:11px;padding:2px 7px;border-radius:10px;color:#06121f}
.sev.critical{background:var(--crit);color:#fff}.sev.high{background:var(--high);color:#fff}
.sev.medium{background:var(--med)}.sev.low{background:var(--low)}.sev.info{background:var(--info);color:#fff}
.status{color:var(--muted);font-size:12px;margin-left:auto}
.note{color:var(--muted);font-size:11px;margin-top:8px}
.count{font-size:12px;color:var(--muted)}
</style></head><body>
<header><h1>sternuke</h1><span class="badge">local dashboard</span>
<span class="status" id="status">idle</span></header>
<main>
 <section class="panel">
  <div class="tabs"><div class="tab active" data-tab="scan">Quick Scan</div>
   <div class="tab" data-tab="orch">Orchestration</div></div>

  <div id="pane-scan">
   <label>Target</label><input id="s-target" value="http://127.0.0.1:8080">
   <div class="row"><div><label>Mode</label>
     <select id="s-mode"><option value="web">web</option><option value="blockchain">blockchain</option></select></div>
    <div><label>Model</label><input id="s-model" value="deepseek-coder"></div></div>
   <div class="checks"><label><input type="checkbox" id="s-ai"> Use local AI agent</label></div>
   <label>Cookie / headers (one per line, for authenticated scans)</label>
   <textarea id="s-headers" placeholder="Cookie: PHPSESSID=abc123; security=low"></textarea>
   <button id="btn-scan">Start scan</button>
  </div>

  <div id="pane-orch" style="display:none">
   <label>Targets (one per line) or paste a scope list</label>
   <textarea id="o-targets" placeholder="*.target.test&#10;https://api.target.test/v1&#10;127.0.0.1:8080&#10;0x0000000000000000000000000000000000000000"></textarea>
   <button class="secondary" id="btn-parse">Parse assets</button>
   <div class="count" id="o-summary"></div>
   <div class="checks">
     <label><input type="checkbox" id="m-web" checked> Web Stateful Chain</label>
     <label><input type="checkbox" id="m-abi"> Advanced ABI Contract Fuzzing</label>
     <label><input type="checkbox" id="m-ai" checked> AI Template Generation Loop</label>
     <label><input type="checkbox" id="o-remote"> Allow non-local targets (I am authorised)</label>
   </div>
   <label>RPC (local node, for ABI fuzzing)</label><input id="o-rpc" value="http://127.0.0.1:8545">
   <label>Chain endpoint path (Web Stateful Chain)</label>
   <input id="o-chainpath" value="/api/v1/cart/checkout">
   <label>Chain params (key=value per line)</label>
   <textarea id="o-chainparams" placeholder="quantity=1&#10;item_id=9"></textarea>
   <label>Cookie / headers (one per line)</label>
   <textarea id="o-headers" placeholder="Cookie: PHPSESSID=abc123; security=low"></textarea>
   <button id="btn-orch">Run orchestration</button>
  </div>
  <div class="note">Assessment tool - authorised targets only. Server bound to localhost.</div>
 </section>

 <section class="panel">
  <strong>Findings</strong> <span class="count" id="f-count"></span>
  <table id="findings"><thead><tr><th>Severity</th><th>Name</th><th>Location</th></tr></thead>
   <tbody></tbody></table>
  <label style="margin-top:14px">Live log</label>
  <div id="log"></div>
 </section>
</main>
<script>
const $=s=>document.querySelector(s);
document.querySelectorAll('.tab').forEach(t=>t.onclick=()=>{
  document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
  t.classList.add('active');
  $('#pane-scan').style.display=t.dataset.tab==='scan'?'block':'none';
  $('#pane-orch').style.display=t.dataset.tab==='orch'?'block':'none';});

let es=null;
function setBusy(b){$('#btn-scan').disabled=b;$('#btn-orch').disabled=b;
  $('#status').textContent=b?'running…':'idle';}
function addLog(l){const el=$('#log');el.textContent+=l+"\\n";el.scrollTop=el.scrollHeight;}
function clearOut(){$('#log').textContent='';$('#findings tbody').innerHTML='';$('#f-count').textContent='';}
function renderFindings(fs){
  const order={critical:0,high:1,medium:2,low:3,info:4};
  fs.sort((a,b)=>(order[a.severity]??9)-(order[b.severity]??9));
  $('#findings tbody').innerHTML=fs.map(f=>`<tr><td><span class="sev ${f.severity}">${f.severity.toUpperCase()}</span></td>
   <td>${esc(f.name)}</td><td>${esc(f.matched_at||f.target||'')}</td></tr>`).join('');
  $('#f-count').textContent=fs.length+' finding(s)';}
function esc(s){return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function stream(){ if(es) es.close(); es=new EventSource('/api/events');
  es.onmessage=e=>{const d=JSON.parse(e.data);
   if(d.type==='log') addLog(d.line);
   else if(d.type==='done'){renderFindings(d.findings);setBusy(false);addLog('[done] '+d.count+' finding(s)');es.close();}
   else if(d.type==='error'){addLog('[error] '+d.message);setBusy(false);es.close();}};}
async function post(url,body){const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify(body)});return r.json();}
$('#btn-scan').onclick=async()=>{clearOut();setBusy(true);stream();
  const r=await post('/api/scan',{target:$('#s-target').value,mode:$('#s-mode').value,
   model:$('#s-model').value,use_ai:$('#s-ai').checked,headers:$('#s-headers').value});
  if(r.error){addLog('[error] '+r.error);setBusy(false);}};
$('#btn-parse').onclick=async()=>{const r=await post('/api/parse',{targets:$('#o-targets').value});
  $('#o-summary').textContent=r.count+' asset(s): '+JSON.stringify(r.summary);};
$('#btn-orch').onclick=async()=>{clearOut();setBusy(true);stream();
  const modes=[];if($('#m-web').checked)modes.push('web_chain');
  if($('#m-abi').checked)modes.push('abi_fuzz');if($('#m-ai').checked)modes.push('ai_templates');
  const r=await post('/api/orchestrate',{targets:$('#o-targets').value,modes,
   rpc_url:$('#o-rpc').value,allow_remote:$('#o-remote').checked,
   chain_path:$('#o-chainpath').value,chain_params:$('#o-chainparams').value,
   headers:$('#o-headers').value});
  if(r.error){addLog('[error] '+r.error);setBusy(false);}};
</script></body></html>"""


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
class WebDashboard:
    """The aiohttp application wiring routes to the assessment loops."""

    def __init__(self, output_dir: str = "./sternuke-out",
                 model: str = "deepseek-coder",
                 base_url: str = "http://localhost:11434/v1") -> None:
        if web is None:  # pragma: no cover
            raise RuntimeError(f"aiohttp is required for the web dashboard: {_AIOHTTP_ERR}")
        self.output_dir = output_dir
        self.model = model
        self.base_url = base_url
        self.jobs = JobManager()
        self.parser = AssetParser()
        self.app = web.Application()
        self.app.add_routes([
            web.get("/", self._index),
            web.post("/api/scan", self._scan),
            web.post("/api/orchestrate", self._orchestrate),
            web.post("/api/parse", self._parse),
            web.get("/api/events", self._events),
        ])

    # -- routes --------------------------------------------------------------
    async def _index(self, _req: "web.Request") -> "web.Response":
        return web.Response(text=_PAGE, content_type="text/html")

    async def _parse(self, req: "web.Request") -> "web.Response":
        data = await req.json()
        assets = self.parser.parse_text(data.get("targets", ""))
        return web.json_response({
            "count": len(assets),
            "summary": self.parser.summary(assets),
            "assets": [a.to_dict() for a in assets],
        })

    async def _scan(self, req: "web.Request") -> "web.Response":
        if self.jobs.busy():
            return web.json_response({"error": "a job is already running"}, status=409)
        data = await req.json()
        from .cli import run_assessment
        target = str(data.get("target", "")).strip()
        if not target:
            return web.json_response({"error": "target is required"}, status=400)

        headers = _headers_from_text(data.get("headers", ""))

        def factory(log_sink):
            return run_assessment(
                target=target, mode=data.get("mode", "web"),
                rules_path=os.path.join(os.path.dirname(__file__), "rules"),
                output_dir=self.output_dir, use_ai=bool(data.get("use_ai")),
                model=data.get("model", self.model), base_url=self.base_url,
                concurrency=15, rps=20.0, verbose=True, headers=headers,
                log_sink=log_sink)

        self.jobs.start("scan", factory)
        return web.json_response({"status": "started"})

    async def _orchestrate(self, req: "web.Request") -> "web.Response":
        if self.jobs.busy():
            return web.json_response({"error": "a job is already running"}, status=409)
        data = await req.json()
        from .cli import run_orchestration
        assets = self.parser.parse_text(data.get("targets", ""))
        if not assets:
            return web.json_response({"error": "no valid targets parsed"}, status=400)
        modes = data.get("modes") or ["web_chain", "ai_templates"]
        headers = _headers_from_text(data.get("headers", ""))
        chain_params = _params_from_text(data.get("chain_params", ""))
        chain_path = data.get("chain_path") or "/api/v1/cart/checkout"

        def factory(log_sink):
            return run_orchestration(
                assets=assets, modes=modes, output_dir=self.output_dir,
                model=self.model, base_url=self.base_url,
                rpc_url=data.get("rpc_url", "http://127.0.0.1:8545"),
                concurrency=15, rps=15.0, verbose=True,
                allow_remote=bool(data.get("allow_remote")),
                chain_path=chain_path, chain_params=chain_params, headers=headers,
                log_sink=log_sink)

        self.jobs.start("orchestrate", factory)
        return web.json_response({"status": "started", "assets": len(assets)})

    async def _events(self, req: "web.Request") -> "web.StreamResponse":
        resp = web.StreamResponse(headers={
            "Content-Type": "text/event-stream", "Cache-Control": "no-cache",
            "Connection": "keep-alive"})
        await resp.prepare(req)
        job = self.jobs.current
        if job is None:
            await resp.write(b"data: {\"type\":\"error\",\"message\":\"no active job\"}\n\n")
            return resp
        # Replay any logs already buffered, then stream live events.
        for line in list(job.logs):
            await resp.write(f"data: {json.dumps({'type': 'log', 'line': line})}\n\n".encode())
        while True:
            try:
                event = await asyncio.wait_for(job.queue.get(), timeout=25)
            except asyncio.TimeoutError:
                await resp.write(b": keep-alive\n\n")   # SSE comment to hold the connection
                continue
            await resp.write(f"data: {json.dumps(event)}\n\n".encode())
            if event.get("type") in ("done", "error"):
                break
        return resp


def serve(host: str = "127.0.0.1", port: int = 8787, *,
          output_dir: str = "./sternuke-out",
          model: str = "deepseek-coder",
          base_url: str = "http://localhost:11434/v1") -> None:
    """Start the local web dashboard (blocking).

    Binds to loopback by default. A non-loopback host is allowed but prints a
    warning because the dashboard has no authentication.
    """
    if web is None:  # pragma: no cover
        raise SystemExit(
            "The web dashboard requires aiohttp. Install with: pip install aiohttp")
    dashboard = WebDashboard(output_dir=output_dir, model=model, base_url=base_url)
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"WARNING: binding to {host} exposes the unauthenticated dashboard "
              f"beyond localhost. Only do this on a trusted network.")
    print(f"sternuke dashboard: http://{host}:{port}  (Ctrl-C to stop)")
    web.run_app(dashboard.app, host=host, port=port, print=None)


if __name__ == "__main__":  # pragma: no cover
    serve()
