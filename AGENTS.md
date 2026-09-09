# AGENTS.md — shipcheck

> Inherits from bus root `../AGENTS.md` (stacks per-project, infra common: git + Dokploy + proxied DNS). This file declares shipcheck stack only.

## What this is
Shipcheck — go-live security audit + rescue + care for AI-built (vibe-coded) apps. Productized ladder: free instant self-check → Audit $99 (48h) → Rescue $299 (scoped fix, 48h or free) → Care $79/mo (monitoring + monthly re-check + 1 fix/mo).
Stack: Node 20 + Express 4 (ESM), static frontend in `public/`, Dockerfile.

Why this, why now (Sep 2026, verified): ~89.5% of AI-built apps ship with vulnerabilities (SusVibes peer-reviewed), ~70% of Supabase-backed vibe apps miss RLS, ~25% leak a secret in the frontend bundle (CVE-2025-48757 exposed 170+ Lovable apps). Free scanners exist — we sell the fix + ongoing care, not the scan. Care-band pricing $25–$500/mo is normal (Teqri $25/50/129, full-service $95–195); $79 sits mid-band. Audit→retainer is the proven 90-day path (Apex Digital $12k/mo line from AI audits in 2026).

## Layout
- `server.js` — serves `public/`, `GET /api/health`, `GET /api/config` (`auditLink`/`rescueLink`/`careLink`), `GET /api/scan?url=` (SSRF-guarded public-surface scan: TLS/headers/CORS/exposed files, rate-limited), `POST /api/intake` (logs `INTAKE <ref>` queue line to runtime logs)
- `public/index.html` — security-console landing built around the LIVE scan demo, honest scope split, code-side self-check, redacted sample $99 report, pay-after-delivery pricing, process, FAQ, intake form
- Intake fulfilment: `INTAKE` lines in Dokploy runtime logs (`application.readLogs`) + email once mailbox exists. Check logs daily.
- `.env` — app keys only (infra lives in bus root `.env`), NOT in repo
- `.env.example` — app template

## Business mechanics
- Funnel: free self-checks + public teardowns in builder communities → paid Audit $99 → Rescue $299 upsell (check finds RLS/secrets) → Care $79/mo attach (card at rescue).
- Math to $3,000 MRR: 38 × $79 = $3,002. 90-day cash funds runtime: 25 audits ($2,475) + 12 rescues ($3,588) + care attach.
- KILL CRITERIA: 0 paid audits from 60 free checks within 30 days of launch → kill shipcheck, report plainly, no sunk-cost theatre.
- Scope guard: Care = uptime + monthly re-check + 1 scoped fix/mo. No unlimited fixes. Rescue ships in 48h or it's free.
- mini.beer stays live but parked (no monetization effort). tend learnings folded in here; tend stays live, no new effort unless inbound.

## Secrets discipline (hard rule)
- NEVER paste token values into commands, code, logs, or chat.
- ALWAYS load split env from inside this dir: `set -a; source ../.env; source .env; set +a` (infra + app), then `$VAR`s.
- GitHub pushes: credential helper with env-var function, never tokens in URLs.
- Customer-facing copy NEVER mentions processors, compliance, or regulators.

## Deploy flow
- Repo `panda-quick-01/shipcheck`, branch `main`, Dokploy app `7-21mEOcP-_PkhiNDhw2i`.
- Staging host: `shipcheck.mini.beer` → `3000` (live 2026-09-09).
- Push → `POST /api/application.deploy` → verify `/api/health` → check Cloudflare headers (`server: cloudflare` + `cf-ray`).

## Identity checkpoints (need the human, on return)
- [ ] GitHub repo created + first push
- [ ] Dokploy app + `shipcheck.mini.beer` domain + TLS
- [ ] Processor account + `STRIPE_AUDIT_LINK` / `STRIPE_RESCUE_LINK` / `STRIPE_CARE_LINK` envs
- [ ] `checks@…` mailbox for intake
