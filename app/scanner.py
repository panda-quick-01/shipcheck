"""Read-only public-surface scanner, v3.

What it does: fetches what a site serves publicly (homepage, JS bundles)
and reports security-relevant misconfigurations plus high-confidence leaked
secrets. What it never does: log in, submit forms, send payloads, brute-force.
"""
import asyncio
import ipaddress
import re
import socket
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpx

TIMEOUT = 8.0
MAX_BODY = 256 * 1024
MAX_BUNDLES = 6
UA = {"User-Agent": "shipcheck-scanner/1.0 (+https://shipcheck.mini.beer)"}


class ScanError(Exception):
    pass


def ip_blocked(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return bool(
        a.is_private
        or a.is_loopback
        or a.is_link_local
        or a.is_multicast
        or a.is_reserved
        or a.is_unspecified
    )


def validate_url(raw):
    """Pure URL policy check (no network). Returns (scheme, host, port)."""
    if not raw or not isinstance(raw, str):
        raise ScanError("pass a URL starting with https://")
    try:
        p = urlsplit(raw.strip())
    except Exception:
        raise ScanError("not a valid URL — include https://")
    if p.scheme not in ("http", "https"):
        raise ScanError("only http(s) URLs")
    if p.username or p.password or "@" in (raw or ""):
        raise ScanError("credentials in URL are not allowed")
    if not p.hostname:
        raise ScanError("not a valid URL — include a hostname")
    port = p.port or (443 if p.scheme == "https" else 80)
    if port not in (80, 443):
        raise ScanError("only ports 80/443")
    if len(p.hostname) > 253:
        raise ScanError("hostname too long")
    return p.scheme, p.hostname.lower(), port


async def resolve_ok(host, port):
    """All resolved addresses must be public, else reject (rebind guard)."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.run_in_executor(None, socket.getaddrinfo, host, port, socket.AF_UNSPEC, socket.SOCK_STREAM),
            timeout=TIMEOUT,
        )
    except Exception:
        raise ScanError("hostname does not resolve")
    ips = {i[4][0] for i in infos}
    if not ips or any(ip_blocked(ip) for ip in ips):
        raise ScanError("target is not a public host")
    return ips


async def fetch_capped(client, url, headers=None, limit=MAX_BODY):
    """GET with manual redirect handling by caller. Returns (status, headers, text)."""
    r = await client.get(url, headers=headers, follow_redirects=False, timeout=TIMEOUT)
    chunks = []
    total = 0
    async for chunk in r.aiter_bytes(65536):
        chunks.append(chunk)
        total += len(chunk)
        if total >= limit:
            break
    await r.aclose()
    raw = b"".join(chunks)[:limit]
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = ""
    return r.status_code, r.headers, text


SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}"), "critical",
     "AWS key is public. Rotate it in IAM now, then move all AWS calls server-side."),
    ("Stripe secret key", re.compile(r"sk_live_[0-9A-Za-z]{16,}"), "critical",
     "Live Stripe secret ships to every visitor. Roll it in the Stripe dashboard, move charges to a server route."),
    ("GitHub token", re.compile(r"(?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,}"), "critical",
     "GitHub token is public. Revoke it on github.com/settings/tokens, audit what it touched."),
    ("Slack token", re.compile(r"xox[bpras]-[0-9A-Za-z-]{10,}"), "high",
     "Slack token is public. Revoke it in Slack admin, rotate, scope to least privilege."),
    ("Private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "critical",
     "A private key is served publicly. Treat it as compromised: replace everywhere it was used."),
    ("Database connection string", re.compile(r"mongodb(?:\+srv)?://[^\s'\"<>]+"), "high",
     "DB credentials in client code. Rotate the password, restrict network access to the database, move queries server-side."),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "medium",
     "Google key is public. Verify HTTP-referrer and API restrictions in Google Cloud console — unrestricted keys get abused."),
]

SUPABASE_RE = re.compile(r"https://[a-z0-9-]{1,60}\.supabase\.co|NEXT_PUBLIC_SUPABASE_[A-Z_]+|sb_publishable_[0-9A-Za-z_-]+")

BUILDERS = [
    ("Lovable", ["lovable.dev", "lovableproject.com"]),
    ("Bolt", ["bolt.new"]),
    ("v0", ["v0.dev"]),
    ("Replit", ["replit.dev", "replit.app"]),
    ("Base44", ["base44"]),
    ("Next.js", ["__NEXT_DATA__", "_next/static"]),
    ("Nuxt", ["__NUXT__"]),
]


class _Scripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.srcs = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            src = dict(attrs).get("src")
            if src:
                self.srcs.append(src)


def scan_text_for_secrets(text):
    out = []
    for name, rx, sev, fix in SECRET_PATTERNS:
        if rx.search(text):
            out.append({"sev": sev, "check": "%s in client bundle" % name,
                        "detail": "Pattern matched code served to every visitor's browser.",
                        "fix": fix})
    return out


def detect_backend_and_builder(text):
    notes = []
    if SUPABASE_RE.search(text):
        notes.append({"sev": "info", "check": "Supabase backend detected",
                      "detail": "App talks to Supabase from the browser. Anon keys are normal there — database access rules are what matter.",
                      "fix": "Deep audit verifies every table's access rules + storage policies. ~7 in 10 AI-built Supabase apps fail this."})
    for name, markers in BUILDERS:
        if any(m in text for m in markers):
            extra = ""
            if name == "Lovable":
                extra = " Lovable's 2025 default left databases open (CVE-2025-48757) — existing apps still need manual review."
            notes.append({"sev": "info", "check": "Built with %s" % name,
                          "detail": ("Fingerprint matched page markers." + extra).strip(),
                          "fix": "Know your builder's historic defaults, then verify instead of trusting them."})
            break
    return notes


def grade(findings):
    sev = [f["sev"] for f in findings]
    if "critical" in sev:
        return "FAIL"
    if "high" in sev or len(findings) >= 3:
        return "AT RISK"
    return "SOLID"


async def scan_host(raw_url):
    scheme, host, port = validate_url(raw_url)
    await resolve_ok(host, port)
    origin = "%s://%s" % (scheme, host)
    findings = []
    async with httpx.AsyncClient(headers=UA, timeout=TIMEOUT) as client:
        # Follow up to 2 redirects, re-validating each hop.
        url = origin + "/"
        home = None
        for _ in range(3):
            status, headers, text = await fetch_capped(client, url)
            if status in (301, 302, 303, 307, 308) and headers.get("location"):
                nxt = urljoin(url, headers["location"])
                s2, h2, _ = validate_url(nxt)
                await resolve_ok(h2, 443 if s2 == "https" else 80)
                url = "%s://%s" % (s2, h2)
                origin = url
                host = h2
                continue
            home = (status, headers, text)
            break
        if home is None:
            raise ScanError("too many redirects")
        status, headers, text = home
        if status >= 500:
            raise ScanError("site returned %s — try again later" % status)

        if urlsplit(url).scheme == "http":
            findings.append({"sev": "high", "check": "No TLS",
                             "detail": "Site serves plain HTTP. Logins, tokens and cookies travel readable.",
                             "fix": "Terminate TLS (host/CDN one-toggle) and 301 http→https."})

        def need(name, why, fix, sev="medium"):
            if not headers.get(name):
                findings.append({"sev": sev, "check": "Missing %s" % name, "detail": why, "fix": fix})

        need("strict-transport-security", "No HSTS — first-visit downgrade attacks stay possible.",
             "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains")
        need("content-security-policy", "No CSP — an XSS flaw becomes full session theft instead of a contained bug.",
             "Ship a tight CSP; start with default-src 'self' and expand by violation reports.")
        need("x-frame-options", "No clickjacking defense — logged-in pages can be framed by an attacker's site.",
             "Add: X-Frame-Options: DENY (or frame-ancestors 'none' in CSP).")
        need("x-content-type-options", "No MIME-sniffing guard — browsers may execute uploads as scripts.",
             "Add: X-Content-Type-Options: nosniff")
        if not headers.get("referrer-policy"):
            findings.append({"sev": "low", "check": "Missing Referrer-Policy",
                             "detail": "Full URLs (possibly with tokens) leak to third parties.",
                             "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin"})
        powered = headers.get("x-powered-by") or headers.get("server")
        if powered and re.search(r"\d", powered):
            findings.append({"sev": "low", "check": "Version disclosure",
                             "detail": 'Server advertises "%s" — narrows attacker targeting.' % powered,
                             "fix": "Hide X-Powered-By; keep Server generic."})

        # CORS reflection probe
        try:
            st, hd, _ = await fetch_capped(client, origin + "/", headers={"Origin": "https://evil.example"})
            acao = hd.get("access-control-allow-origin")
            acac = hd.get("access-control-allow-credentials")
            if acao == "https://evil.example" and (acac or "").lower() == "true":
                findings.append({"sev": "critical", "check": "CORS origin reflection + credentials",
                                 "detail": "Any website can make authenticated requests as your users and read the answers.",
                                 "fix": "Allowlist exact origins via env var. Never reflect Origin with credentials."})
            elif acao == "*":
                findings.append({"sev": "low", "check": "CORS wildcard",
                                 "detail": "Any origin may read unauthenticated responses. Fine for public data, fatal with credentials.",
                                 "fix": "Scope to your domains unless the endpoint is intentionally public."})
        except Exception:
            pass

        # Exposed-file probes (public paths, read-only GETs)
        probes = [
            ("/.env", lambda b: ("=" in b) and bool(re.search(r"KEY|SECRET|PASSWORD|TOKEN", b, re.I)),
             "Exposed .env file", "critical",
             "Production secrets readable by anyone. Rotate every key, remove it from the web root, never deploy it."),
            ("/.git/HEAD", lambda b: "ref:" in b, "Exposed .git", "critical",
             "Attackers can reconstruct source and hunt secrets in history. Stop serving .git, rotate any secret ever committed."),
            ("/server-status", lambda b: bool(re.search(r"Apache Status|requests currently", b, re.I)), "Exposed server-status", "medium",
             "Internal process info visible to the internet. Restrict to localhost / require auth."),
        ]
        for path, match, check, sev, fix in probes:
            try:
                st, _, body = await fetch_capped(client, origin + path, limit=16384)
                if st == 200 and match(body):
                    findings.append({"sev": sev, "check": check,
                                     "detail": "%s is publicly readable." % (origin + path), "fix": fix})
            except Exception:
                pass

        # JS bundle mining: secrets + fingerprints + source maps
        parser = _Scripts()
        try:
            parser.feed(text)
        except Exception:
            pass
        seen = set()
        for src in parser.srcs:
            if len(seen) >= MAX_BUNDLES:
                break
            full = urljoin(origin + "/", src)
            try:
                sp = urlsplit(full)
                if sp.scheme not in ("http", "https"):
                    continue
            except Exception:
                continue
            if full in seen:
                continue
            seen.add(full)
            try:
                st, _, js = await fetch_capped(client, full)
            except Exception:
                continue
            if st != 200 or not js:
                continue
            findings.extend(scan_text_for_secrets(js))
            findings.extend(detect_backend_and_builder(js))
            try:
                mst, _, mmap = await fetch_capped(client, full + ".map", limit=16384)
                if mst == 200 and '"sources"' in mmap:
                    findings.append({"sev": "medium", "check": "Source maps exposed",
                                     "detail": "Original source for %s is downloadable." % src,
                                     "fix": "Don't deploy .map files to production (disable in build config)."})
            except Exception:
                pass
        findings.extend(detect_backend_and_builder(text))

    # De-dupe identical (sev, check) pairs, keep order.
    uniq, keys = [], set()
    for f in findings:
        k = (f["sev"], f["check"])
        if k not in keys:
            keys.add(k)
            uniq.append(f)
    return {"ok": True, "host": host, "grade": grade(uniq), "findings": uniq,
            "scannedAt": datetime.now(timezone.utc).isoformat(),
            "note": "Public surface only — database rules, bundle-excluded logic and auth flows need the $99 deep audit."}
