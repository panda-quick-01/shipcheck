"""Persistence: Postgres when DATABASE_URL is set, else local SQLite.

Same schema and behaviour on both backends. IDs are generated client-side
so neither backend needs RETURNING handling. Secrets (project keys) are
stored as sha256 hashes only.
"""
import asyncio
import hashlib
import hmac
import json
import os
import secrets as pysecrets
import sqlite3
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  host TEXT UNIQUE NOT NULL,
  key_hash TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  last_scan_at TEXT
);
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  project_id TEXT,
  host TEXT NOT NULL,
  grade TEXT NOT NULL,
  n_findings INTEGER NOT NULL,
  n_critical INTEGER NOT NULL,
  findings TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS intakes (
  ref TEXT PRIMARY KEY,
  tier TEXT NOT NULL,
  url TEXT NOT NULL,
  stack TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
"""

mode = "sqlite"
_pool = None
_db_path = os.environ.get("SHIPCHECK_DATA", os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "shipcheck.db"))


def now():
    return datetime.now(timezone.utc).isoformat()


def _hash_key(key):
    return hashlib.sha256(key.encode()).hexdigest()


async def init():
    global mode, _pool
    dsn = os.environ.get("DATABASE_URL")
    if dsn:
        try:
            import asyncpg  # lazy: only needed for Postgres mode
            _pool = await asyncio.wait_for(asyncpg.create_pool(dsn, min_size=1, max_size=5), timeout=8)
            async with _pool.acquire() as c:
                await c.execute(SCHEMA)
            mode = "postgres"
            return
        except Exception:
            _pool = None
    os.makedirs(os.path.dirname(_db_path), exist_ok=True)
    await asyncio.to_thread(_sqlite_init)
    mode = "sqlite"


def _sqlite_init():
    c = sqlite3.connect(_db_path)
    c.executescript(SCHEMA)
    c.commit()
    c.close()


def _sqlite_run(fn, *args):
    def go():
        c = sqlite3.connect(_db_path)
        c.row_factory = sqlite3.Row
        try:
            out = fn(c, *args)
            c.commit()
            return out
        finally:
            c.close()
    return go


# ---- projects ----
async def create_project(host, name=""):
    pid = "p_" + pysecrets.token_hex(6)
    key = "sk_" + pysecrets.token_hex(16)
    kh = _hash_key(key)
    ts = now()
    if _pool:
        async with _pool.acquire() as c:
            try:
                await c.execute(
                    "INSERT INTO projects(id,host,key_hash,name,created_at) VALUES($1,$2,$3,$4,$5)",
                    pid, host, kh, name or host, ts)
            except Exception as e:
                if "unique" in str(e).lower():
                    return None, None
                raise
    else:
        def go(c):
            try:
                c.execute("INSERT INTO projects(id,host,key_hash,name,created_at) VALUES(?,?,?,?,?)",
                          (pid, host, kh, name or host, ts))
            except sqlite3.IntegrityError:
                return None
            return True
        if await asyncio.to_thread(_sqlite_run(go)) is None:
            return None, None
    return pid, key


async def get_project(pid):
    if _pool:
        async with _pool.acquire() as c:
            r = await c.fetchrow("SELECT id,host,name,created_at,last_scan_at FROM projects WHERE id=$1", pid)
            return dict(r) if r else None
    def go(c):
        r = c.execute("SELECT id,host,name,created_at,last_scan_at FROM projects WHERE id=?", (pid,)).fetchone()
        return dict(r) if r else None
    return await asyncio.to_thread(_sqlite_run(go))


async def check_key(pid, key):
    if not key:
        return False
    want = _hash_key(key)
    if _pool:
        async with _pool.acquire() as c:
            r = await c.fetchrow("SELECT key_hash FROM projects WHERE id=$1", pid)
            got = r["key_hash"] if r else ""
    else:
        def go(c):
            r = c.execute("SELECT key_hash FROM projects WHERE id=?", (pid,)).fetchone()
            return r["key_hash"] if r else ""
        got = await asyncio.to_thread(_sqlite_run(go))
    return bool(got) and hmac.compare_digest(got, want)


async def touch_project(pid, ts):
    if _pool:
        async with _pool.acquire() as c:
            await c.execute("UPDATE projects SET last_scan_at=$1 WHERE id=$2", ts, pid)
    else:
        def go(c):
            c.execute("UPDATE projects SET last_scan_at=? WHERE id=?", (ts, pid))
        await asyncio.to_thread(_sqlite_run(go))


async def projects_due(limit=10):
    """Projects never scanned or not scanned in 7 days."""
    if _pool:
        async with _pool.acquire() as c:
            rows = await c.fetch(
                "SELECT id,host FROM projects WHERE last_scan_at IS NULL "
                "OR last_scan_at < (NOW() - INTERVAL '7 days') ORDER BY created_at LIMIT $1", limit)
            return [dict(r) for r in rows]
    def go(c):
        rows = c.execute(
            "SELECT id,host FROM projects WHERE last_scan_at IS NULL "
            "OR last_scan_at < datetime('now','-7 days') ORDER BY created_at LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
    return await asyncio.to_thread(_sqlite_run(go))


# ---- scans ----
async def add_scan(project_id, host, grade, findings):
    sid = "s_" + pysecrets.token_hex(8)
    ts = now()
    blob = json.dumps(findings)
    ncrit = sum(1 for f in findings if f.get("sev") == "critical")
    if _pool:
        async with _pool.acquire() as c:
            await c.execute(
                "INSERT INTO scans(id,project_id,host,grade,n_findings,n_critical,findings,created_at)"
                " VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
                sid, project_id, host, grade, len(findings), ncrit, blob, ts)
    else:
        def go(c):
            c.execute(
                "INSERT INTO scans(id,project_id,host,grade,n_findings,n_critical,findings,created_at)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (sid, project_id, host, grade, len(findings), ncrit, blob, ts))
        await asyncio.to_thread(_sqlite_run(go))
    if project_id:
        await touch_project(project_id, ts)
    # Bound anonymous-scan growth.
    if not project_id:
        await prune_anonymous()
    return sid


async def history(project_id, limit=20):
    if _pool:
        async with _pool.acquire() as c:
            rows = await c.fetch(
                "SELECT id,host,grade,n_findings,n_critical,created_at FROM scans"
                " WHERE project_id=$1 ORDER BY created_at DESC LIMIT $2", project_id, limit)
            return [dict(r) for r in rows]
    def go(c):
        rows = c.execute(
            "SELECT id,host,grade,n_findings,n_critical,created_at FROM scans"
            " WHERE project_id=? ORDER BY created_at DESC LIMIT ?", (project_id, limit)).fetchall()
        return [dict(r) for r in rows]
    return await asyncio.to_thread(_sqlite_run(go))


async def latest_scan(project_id):
    h = await history(project_id, 1)
    if not h:
        return None
    sid = h[0]["id"]
    if _pool:
        async with _pool.acquire() as c:
            r = await c.fetchrow("SELECT findings FROM scans WHERE id=$1", sid)
            h[0]["findings"] = json.loads(r["findings"])
            return h[0]
    def go(c):
        r = c.execute("SELECT findings FROM scans WHERE id=?", (sid,)).fetchone()
        return json.loads(r["findings"])
    h[0]["findings"] = await asyncio.to_thread(_sqlite_run(go))
    return h[0]


async def prune_anonymous(keep=500):
    if _pool:
        async with _pool.acquire() as c:
            await c.execute(
                "DELETE FROM scans WHERE project_id IS NULL AND id NOT IN "
                "(SELECT id FROM scans WHERE project_id IS NULL ORDER BY created_at DESC LIMIT $1)", keep)
    else:
        def go(c):
            c.execute(
                "DELETE FROM scans WHERE project_id IS NULL AND id NOT IN "
                "(SELECT id FROM scans WHERE project_id IS NULL ORDER BY created_at DESC LIMIT ?)", (keep,))
        await asyncio.to_thread(_sqlite_run(go))


async def stats():
    if _pool:
        async with _pool.acquire() as c:
            n = await c.fetchval("SELECT COUNT(*) FROM scans")
            f = await c.fetchval("SELECT COUNT(*) FROM scans WHERE grade='FAIL'")
            hosts = await c.fetchval("SELECT COUNT(DISTINCT host) FROM scans")
    else:
        def go(c):
            n = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            f = c.execute("SELECT COUNT(*) FROM scans WHERE grade='FAIL'").fetchone()[0]
            hosts = c.execute("SELECT COUNT(DISTINCT host) FROM scans").fetchone()[0]
            return n, f, hosts
        n, f, hosts = await asyncio.to_thread(_sqlite_run(go))
    return {"scans": n, "fail_pct": round(100.0 * f / n) if n else 0, "hosts": hosts}


# ---- intakes ----
async def add_intake(ref, tier, url, stack, notes):
    ts = now()
    if _pool:
        async with _pool.acquire() as c:
            await c.execute(
                "INSERT INTO intakes(ref,tier,url,stack,notes,created_at) VALUES($1,$2,$3,$4,$5,$6)",
                ref, tier, url, stack, notes, ts)
    else:
        def go(c):
            c.execute("INSERT INTO intakes(ref,tier,url,stack,notes,created_at) VALUES(?,?,?,?,?,?)",
                      (ref, tier, url, stack, notes, ts))
        await asyncio.to_thread(_sqlite_run(go))
