import express from "express";
import path from "path";
import dns from "dns";
import net from "net";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.disable("x-powered-by");
app.use(express.json({ limit: "16kb" }));

// Dogfood: the headers we sell. Self-scan must pass.
app.use((req, res, next) => {
  res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' https://cdn.tailwindcss.com 'unsafe-inline'; style-src 'self' https://cdn.tailwindcss.com 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
  );
  next();
});

app.use(express.static(path.join(__dirname, "public"), { maxAge: "1h", dotfiles: "ignore" }));

app.get("/api/health", (req, res) => {
  res.json({ ok: true, service: "shipcheck", time: new Date().toISOString() });
});

app.get("/api/config", (req, res) => {
  res.json({
    auditLink: process.env.STRIPE_AUDIT_LINK || "",
    rescueLink: process.env.STRIPE_RESCUE_LINK || "",
    careLink: process.env.STRIPE_CARE_LINK || "",
  });
});

// ---------- public-surface scanner ----------
const SCAN_TIMEOUT_MS = 8000;
const SCAN_MAX_BYTES = 64 * 1024;

function isBlockedIp(ip) {
  if (!net.isIP(ip)) return true;
  if (net.isIPv4(ip)) {
    const o = ip.split(".").map(Number);
    if (o[0] === 10) return true;
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
    if (o[0] === 192 && o[1] === 168) return true;
    if (o[0] === 127) return true;
    if (o[0] === 169 && o[1] === 254) return true;
    if (o[0] === 0 || o[0] >= 224) return true;
    return false;
  }
  // IPv6: block everything except global unicast
  const lo = ip.toLowerCase();
  if (lo === "::1" || lo === "::") return true;
  if (lo.startsWith("fe80:") || lo.startsWith("fec0:") || lo.startsWith("fc") || lo.startsWith("fd")) return true;
  if (lo.startsWith("ff")) return true;
  return false;
}

async function safeUrl(raw) {
  let u;
  try {
    u = new URL(raw.trim());
  } catch {
    throw new Error("not a valid URL — include https://");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("only http(s) URLs");
  if (u.username || u.password || raw.includes("@")) throw new Error("credentials in URL are not allowed");
  if (![80, 443].includes(u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80))
    throw new Error("only ports 80/443");
  let addrs;
  try {
    addrs = await dns.promises.lookup(u.hostname, { all: true });
  } catch {
    throw new Error("hostname does not resolve");
  }
  if (addrs.some((a) => isBlockedIp(a.address))) throw new Error("target is not a public host");
  u.hash = "";
  return u;
}

async function fetchCapped(url, opts = {}) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), SCAN_TIMEOUT_MS);
  try {
    const r = await fetch(url, { ...opts, signal: ctl.signal, redirect: "manual" });
    const buf = Buffer.from(await r.arrayBuffer().then((b) => b.slice(0, SCAN_MAX_BYTES)));
    return { r, body: buf.toString("utf8", 0, Math.min(buf.length, 4000)) };
  } finally {
    clearTimeout(t);
  }
}

// 15 scans / 10 min per IP — generous for humans, useless for abuse.
const buckets = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const arr = (buckets.get(ip) || []).filter((t) => now - t < 10 * 60 * 1000);
  arr.push(now);
  buckets.set(ip, arr);
  return arr.length > 15;
}

app.get("/api/scan", async (req, res) => {
  try {
    if (rateLimited(req.ip)) return res.status(429).json({ ok: false, error: "slow down — try again in a few minutes" });
    if (!req.query.url) return res.status(400).json({ ok: false, error: "pass ?url=https://your-app.com" });
    const target = await safeUrl(String(req.query.url));
    const base = target.origin;
    const findings = [];

    // 1. TLS
    if (target.protocol === "http:") {
      findings.push({ sev: "high", check: "No TLS", detail: "Site serves plain HTTP. Logins, tokens and cookies travel readable.", fix: "Terminate TLS (your host/CDN does this in one toggle) and 301 http→https." });
    }

    // 2. Homepage fetch
    let home;
    try {
      home = await fetchCapped(base + "/", { headers: { "User-Agent": "shipcheck-scanner/1.0" } });
    } catch {
      return res.json({ ok: false, error: "could not reach the site (timeout or refused). Is it public?" });
    }
    const h = home.r.headers;
    const need = (name, why, fix) => {
      if (!h.get(name)) findings.push({ sev: "medium", check: `Missing ${name}`, detail: why, fix });
    };
    need("strict-transport-security", "No HSTS — first-visit downgrade attacks stay possible.", "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains");
    need("content-security-policy", "No CSP — an XSS flaw becomes full session theft instead of a contained bug.", "Ship a tight CSP; start with default-src 'self' and expand by violation reports.");
    need("x-frame-options", "No clickjacking defense — your logged-in pages can be framed by an attacker's site.", "Add: X-Frame-Options: DENY (or frame-ancestors 'none' in CSP).");
    need("x-content-type-options", "No MIME-sniffing guard — browsers may execute uploads as scripts.", "Add: X-Content-Type-Options: nosniff");
    if (!h.get("referrer-policy")) findings.push({ sev: "low", check: "Missing Referrer-Policy", detail: "Full URLs (possibly with tokens) leak to third parties.", fix: "Add: Referrer-Policy: strict-origin-when-cross-origin" });
    const powered = h.get("x-powered-by") || h.get("server");
    if (powered && /\d/.test(powered))
      findings.push({ sev: "low", check: "Version disclosure", detail: `Server advertises "${powered}" — narrows attacker targeting.`, fix: "Hide X-Powered-By; keep Server generic." });

    // 3. CORS reflection test
    try {
      const { r } = await fetchCapped(base + "/", { headers: { Origin: "https://evil.example" } });
      const acao = r.headers.get("access-control-allow-origin");
      const acac = r.headers.get("access-control-allow-credentials");
      if (acao === "https://evil.example" && acac === "true")
        findings.push({ sev: "critical", check: "CORS origin reflection + credentials", detail: "Any website can make authenticated requests as your users and read the answers.", fix: "Allowlist exact origins via env var. Never reflect Origin with credentials." });
      else if (acao === "*")
        findings.push({ sev: "low", check: "CORS wildcard", detail: "Any origin may read unauthenticated responses. Harmless for public data, fatal combined with credentials.", fix: "Scope to your domains unless the endpoint is intentionally public." });
    } catch {
      /* unreachable for OPTIONS-style probe — skip, don't fail the scan */
    }

    // 4. Exposed-file probes (public paths only, read-only GETs)
    const probes = [
      ["/.env", (b) => b.includes("=") && /KEY|SECRET|PASSWORD|TOKEN/i.test(b), "Exposed .env file", "Production secrets readable by anyone. Rotate every key in the file, remove it from the web root, never deploy it again."],
      ["/.git/HEAD", (b) => b.includes("ref:"), "Exposed .git", "Attackers can reconstruct source and hunt secrets in history.", "Stop serving .git (host ignore rule), rotate any secret ever committed."],
      ["/server-status", (b) => /Apache Status|requests currently/i.test(b), "Exposed server-status", "Internal process info visible to the internet.", "Restrict to localhost / require auth."],
    ];
    for (const [p, match, check, fix] of probes) {
      try {
        const { r, body } = await fetchCapped(base + p);
        if (r.status === 200 && match(body))
          findings.push({ sev: "critical", check, detail: `${base + p} is publicly readable.`, fix });
      } catch {
        /* probe failed — treat as not exposed */
      }
    }

    const crit = findings.filter((f) => f.sev === "critical").length;
    const highs = findings.filter((f) => f.sev === "high").length;
    const grade = crit > 0 ? "FAIL" : highs > 0 || findings.length >= 3 ? "AT RISK" : "SOLID";
    res.json({ ok: true, host: target.host, grade, findings, scannedAt: new Date().toISOString(), note: "Public surface only — database rules, secrets in your bundle and auth logic need the $99 deep audit." });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

// ---------- intake (fulfilment queue = runtime logs) ----------
app.post("/api/intake", (req, res) => {
  const { url = "", stack = "", notes = "", tier = "audit" } = req.body || {};
  if (!String(url).startsWith("http")) return res.status(400).json({ ok: false, error: "include your live app URL starting with http(s)" });
  if (!["audit", "rescue", "care"].includes(tier)) return res.status(400).json({ ok: false, error: "unknown tier" });
  const ref = "SC-" + Date.now().toString(36).toUpperCase() + "-" + Math.random().toString(36).slice(2, 6).toUpperCase();
  console.log(`INTAKE ${ref} tier=${tier} url=${url} stack=${String(stack).slice(0, 120)} notes=${String(notes).slice(0, 500)}`);
  res.json({ ok: true, ref, message: "Request logged. We reply within 24h with scope + start time." });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`shipcheck listening on :${PORT}`);
});
