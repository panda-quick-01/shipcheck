import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="shipcheck-test-")
os.environ["SHIPCHECK_DATA"] = os.path.join(_tmp, "test.db")
os.environ.pop("DATABASE_URL", None)

from fastapi.testclient import TestClient

from app.main import app


def _client():
    return TestClient(app)


def test_health():
    with _client() as c:
        r = c.get("/api/health")
        assert r.status_code == 200
        d = r.json()
        assert d["ok"] and d["service"] == "shipcheck" and d["db"] == "sqlite"


def test_config_shape():
    with _client() as c:
        d = c.get("/api/config").json()
        assert set(d) == {"auditLink", "rescueLink", "careLink"}


def test_intake_validation():
    with _client() as c:
        assert c.post("/api/intake", json={}).status_code == 400
        assert c.post("/api/intake", json={"url": "notaurl", "tier": "audit"}).status_code == 400
        r = c.post("/api/intake", json={"url": "https://example.com", "tier": "audit", "stack": "t", "notes": "n"})
        assert r.status_code == 200 and r.json()["ok"] and r.json()["ref"].startswith("SC-")


def test_scan_validation_no_network():
    with _client() as c:
        assert c.get("/api/scan").status_code == 400
        assert c.get("/api/scan", params={"url": "ftp://x.com/"}).status_code == 400
        # loopback rejected by SSRF guard (IP literal: no external DNS needed)
        r = c.get("/api/scan", params={"url": "http://127.0.0.1/"})
        assert r.status_code == 400 and "public host" in r.json()["error"]


def test_projects_validation_no_network():
    with _client() as c:
        assert c.post("/api/projects", json={}).status_code == 400
        r = c.get("/api/projects/nope/history", params={"key": "x"})
        assert r.status_code == 403


def test_routing():
    with _client() as c:
        assert c.get("/.env").status_code == 404
        assert c.get("/.git/HEAD").status_code == 404
        assert c.get("/").status_code == 200
        assert c.get("/p/nope").status_code == 404
