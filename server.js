import express from "express";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { maxAge: "1h" }));

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

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`shipcheck listening on :${PORT}`);
});
