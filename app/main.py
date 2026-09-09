"""Shipcheck v3: continuous go-live security watching for AI-built apps."""
import logging
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import scanner, store

log = logging.getLogger("shipcheck")
templates = Jinja2Templates(directory="templates")

_hits = defaultdict(list)


def rate_limited(ip):
    now = time.time()
    arr = [t for t in _hits[ip] if now - t < 600]
    arr.append(now)
    _hits[ip] = arr
    return len(arr) > 15


async def sweep():
    """Hourly: re-scan projects due for their weekly check."""
    try:
        due = await store.projects_due(limit=10)
    except Exception as e:
        log.warning("sweep store error: %s", e)
        return
    for p in due:
        try:
            res = await scanner.scan_host("https://" + p["host"])
            await store.add_scan(p["id"], res["host"], res["grade"], res["findings"])
            log.info("sweep %s -> %s (%d findings)", p["host"], res["grade"], len(res["findings"]))
        except Exception as e:
            log.warning("sweep %s failed: %s", p["host"], e)


@asynccontextmanager
async def lifespan(app):
    await store.init()
    log.info("store mode: %s", store.mode)
    sched = AsyncIOScheduler()
    sched.add_job(sweep, "interval", hours=1)
    sched.start()
    yield
    sched.shutdown()


app = FastAPI(lifespan=lifespan)


@app.middleware("http")
async def security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' https://cdn.tailwindcss.com 'unsafe-inline'; "
        "style-src 'self' https://cdn.tailwindcss.com 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'"
    )
    return resp


app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/api/health")
async def health():
    return {"ok": True, "service": "shipcheck",
            "time": datetime.now(timezone.utc).isoformat(),
            "db": store.mode, "version": 3}


@app.get("/api/config")
async def config():
    import os
    return {"auditLink": os.environ.get("STRIPE_AUDIT_LINK", ""),
            "rescueLink": os.environ.get("STRIPE_RESCUE_LINK", ""),
            "careLink": os.environ.get("STRIPE_CARE_LINK", "")}


@app.get("/api/scan")
async def scan(url: str = ""):
    if rate_limited("scan"):
        return JSONResponse({"ok": False, "error": "slow down — try again in a few minutes"}, status_code=429)
    if not url:
        return JSONResponse({"ok": False, "error": "pass ?url=https://your-app.com"}, status_code=400)
    try:
        res = await scanner.scan_host(url)
    except scanner.ScanError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    except Exception:
        log.exception("scan failed")
        return JSONResponse({"ok": False, "error": "scan failed — try again in a minute"}, status_code=502)
    try:
        await store.add_scan(None, res["host"], res["grade"], res["findings"])
    except Exception:
        log.warning("anonymous scan not stored")
    return res


@app.post("/api/projects")
async def create_project(req: Request):
    try:
        body = await req.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "send JSON {host}"}, status_code=400)
    host = str(body.get("host", "")).strip()
    name = str(body.get("name", "")).strip()[:80]
    try:
        scheme, clean_host, _ = scanner.validate_url(host if "://" in host else "https://" + host)
        await scanner.resolve_ok(clean_host, 443)
    except scanner.ScanError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    pid, key = await store.create_project(clean_host, name)
    if not pid:
        return JSONResponse({"ok": False, "error": "that host is already watched — use your project link"}, status_code=409)
    try:
        res = await scanner.scan_host(scheme + "://" + clean_host)
        await store.add_scan(pid, res["host"], res["grade"], res["findings"])
    except Exception as e:
        res = {"ok": False, "error": "project created but first scan failed: %s" % e}
    return {"ok": True, "id": pid, "key": key,
            "dashboard": "/p/%s?key=%s" % (pid, key),
            "note": "Save this link — the key is shown once. Weekly re-scans start automatically.",
            "scan": res}


@app.get("/api/projects/{pid}/history")
async def project_history(pid: str, key: str = Query("")):
    if not await store.check_key(pid, key):
        return JSONResponse({"ok": False, "error": "wrong or missing key"}, status_code=403)
    return {"ok": True, "history": await store.history(pid)}


@app.post("/api/intake")
async def intake(req: Request):
    try:
        body = await req.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "send JSON"}, status_code=400)
    url = str(body.get("url", ""))
    tier = str(body.get("tier", "audit"))
    stack = str(body.get("stack", ""))[:120]
    notes = str(body.get("notes", ""))[:500]
    if not url.startswith("http"):
        return JSONResponse({"ok": False, "error": "include your live app URL starting with http(s)"}, status_code=400)
    if tier not in ("audit", "rescue", "care"):
        return JSONResponse({"ok": False, "error": "unknown tier"}, status_code=400)
    import secrets as pysecrets
    ref = "SC-" + datetime.now(timezone.utc).strftime("%y%m%d") + "-" + pysecrets.token_hex(2).upper()
    try:
        await store.add_intake(ref, tier, url, stack, notes)
    except Exception:
        log.warning("intake not stored")
    print("INTAKE %s tier=%s url=%s stack=%s notes=%s" % (ref, tier, url, stack, notes), flush=True)
    return {"ok": True, "ref": ref, "message": "Request logged. We reply within 24h with scope + start time."}


@app.get("/", response_class=HTMLResponse)
async def landing(request: Request):
    try:
        stats = await store.stats()
    except Exception:
        stats = {"scans": 0, "fail_pct": 0, "hosts": 0}
    return templates.TemplateResponse(request, "landing.html", {"stats": stats})


@app.get("/p/{pid}", response_class=HTMLResponse)
async def dashboard(request: Request, pid: str, key: str = Query("")):
    proj = await store.get_project(pid)
    if not proj:
        return HTMLResponse("<h1>no such project</h1>", status_code=404)
    if not await store.check_key(pid, key):
        return HTMLResponse(
            "<body style='background:#0A0E13;color:#E8EEF5;font-family:monospace;padding:40px'>"
            "<h1>key required</h1><p>Open this dashboard with the full link we gave at creation "
            "(it carries ?key=). Lost it? Request a fresh audit and mention the host.</p></body>",
            status_code=403)
    latest = await store.latest_scan(pid)
    hist = await store.history(pid)
    return templates.TemplateResponse(request, "project.html",
                                      {"proj": proj, "latest": latest, "hist": hist})


@app.get("/{path:path}")
async def catch_all(path: str, request: Request):
    if "/." in ("/" + path):
        return PlainTextResponse("not found", status_code=404)
    try:
        stats = await store.stats()
    except Exception:
        stats = {"scans": 0, "fail_pct": 0, "hosts": 0}
    return templates.TemplateResponse(request, "landing.html", {"stats": stats})
