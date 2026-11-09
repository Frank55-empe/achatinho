import "dotenv/config";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { q, initDb } from "./db.js";

const {
  VERIFY_TOKEN, IG_APP_SECRET, ADMIN_TOKEN, PORT = 3000,
  IG_ACCOUNTS = "{}", DRY_RUN = "false",
  GRAPH_BASE = "https://graph.instagram.com", GRAPH_VERSION = "v23.0",
} = process.env;
const here = path.dirname(fileURLToPath(import.meta.url));

let tokens = {};
try { tokens = JSON.parse(IG_ACCOUNTS); } catch { console.error("IG_ACCOUNTS não é um JSON válido"); }

const app = express();
app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } }));

function saveEvent(type, payload = {}) {
  console.log(`[${type}]`, JSON.stringify(payload).slice(0, 300));
  q("insert into events (type, ig_id, payload) values ($1, $2, $3)", [type, payload.igId ?? null, payload])
    .catch((e) => console.error("não consegui gravar o log:", e.message));
}

const safeEq = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

function validSignature(req) {
  if (!IG_APP_SECRET) return false;
  const expected = "sha256=" + crypto.createHmac("sha256", IG_APP_SECRET).update(req.rawBody || "").digest("hex");
  return safeEq(req.get("x-hub-signature-256") || "", expected);
}

// ---------- Regras ----------
const norm = (s) => String(s || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").trim();
const cleanTag = (t) => String(t).trim().toLowerCase().slice(0, 30);

function loadRules() {
  try { return JSON.parse(fs.readFileSync(path.join(here, "rules.json"), "utf8")); }
  catch (e) { saveEvent("rules_error", { error: e.message }); return []; }
}

function findRule(igId, mediaId, text) {
  const t = norm(text);
  return loadRules().find((r) => {
    if (r.account && r.account !== "*" && r.account !== igId) return false;
    if (r.media && r.media !== "*" && !(Array.isArray(r.media) ? r.media : [r.media]).includes(mediaId)) return false;
    return (r.keywords || []).some((k) => (r.match === "exact" ? t === norm(k) : t.includes(norm(k))));
  });
}

// ---------- Private reply ----------
async function sendPrivateReply(igId, commentId, text) {
  const res = await fetch(`${GRAPH_BASE}/${GRAPH_VERSION}/${igId}/messages`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${tokens[igId]}` },
    body: JSON.stringify({ recipient: { comment_id: commentId }, message: { text } }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${JSON.stringify(data)}`);
  return data;
}

async function handleComment(igId, c) {
  if (!c.id || c.from?.id === igId) return;               // ignora a própria conta
  const rule = findRule(igId, c.media?.id, c.text);
  if (!rule) return saveEvent("no_rule", { igId, commentId: c.id, text: c.text });

  // Reserva o comentário no banco: se já existia, é reenvio da Meta
  const claim = await q("insert into handled_comments (comment_id) values ($1) on conflict do nothing", [c.id]);
  if (!claim.rowCount) return;

  if (c.from?.id) {
    await q(
      `insert into contacts (ig_id, scoped_id, username, tags, comments) values ($1, $2, $3, $4, 1)
       on conflict (ig_id, scoped_id) do update set
         username = coalesce(excluded.username, contacts.username),
         last_seen = now(), comments = contacts.comments + 1,
         tags = array(select distinct unnest(contacts.tags || excluded.tags))`,
      [igId, c.from.id, c.from.username ?? null, (rule.tags || []).map(cleanTag)]
    );
  }

  if (!tokens[igId]) return saveEvent("no_token", { igId, commentId: c.id });
  const text = String(rule.reply).replaceAll("{{username}}", c.from?.username || "");
  if (DRY_RUN === "true") return saveEvent("dry_run", { igId, commentId: c.id, rule: rule.name, text });

  try {
    const result = await sendPrivateReply(igId, c.id, text);
    saveEvent("reply_sent", { igId, commentId: c.id, rule: rule.name, to: c.from?.username, result });
  } catch (e) {
    saveEvent("reply_error", { igId, commentId: c.id, rule: rule.name, error: e.message });
  }
}

// ---------- Webhook ----------
app.get("/", (_req, res) => res.send("manychat-clone no ar"));

app.get("/webhook", (req, res) => {
  if (req.query["hub.mode"] === "subscribe" && req.query["hub.verify_token"] === VERIFY_TOKEN) {
    saveEvent("verify_ok");
    return res.status(200).send(req.query["hub.challenge"]);
  }
  saveEvent("verify_fail");
  res.sendStatus(403);
});

app.post("/webhook", (req, res) => {
  if (!validSignature(req)) { saveEvent("bad_signature"); return res.sendStatus(401); }
  res.sendStatus(200);
  for (const entry of req.body.entry || []) {
    for (const change of entry.changes || []) {
      saveEvent(`change:${change.field}`, { igId: entry.id, value: change.value });
      if (change.field === "comments")
        handleComment(entry.id, change.value).catch((e) => saveEvent("handler_error", { igId: entry.id, error: e.message }));
    }
    for (const msg of entry.messaging || []) saveEvent("messaging", { igId: entry.id, msg });
  }
});

// ---------- Painel e API (protegidos por ADMIN_TOKEN) ----------
const auth = (req, res, next) => {
  const t = (req.get("authorization") || "").replace(/^Bearer /, "");
  if (!ADMIN_TOKEN || !safeEq(t, ADMIN_TOKEN)) return res.sendStatus(401);
  next();
};
const wrap = (fn) => (req, res) => fn(req, res).catch((e) => { console.error(e); res.sendStatus(500); });

app.get("/admin", (_req, res) => res.sendFile(path.join(here, "public", "admin.html")));

app.get("/api/stats", auth, wrap(async (_req, res) => {
  const { rows } = await q(`select
    (select count(*) from events where type = 'reply_sent' and at > now() - interval '24 hours')::int as sent,
    (select count(*) from events where type in ('reply_error','no_token','handler_error') and at > now() - interval '24 hours')::int as errors,
    (select count(*) from contacts)::int as contacts`);
  res.json(rows[0]);
}));

app.get("/api/logs", auth, wrap(async (req, res) => {
  const types = String(req.query.type || "").split(",").filter(Boolean);
  const limit = Math.min(Number(req.query.limit) || 100, 200);
  const { rows } = await q(
    `select id, at, type, ig_id, payload from events ${types.length ? "where type = any($1)" : ""} order by id desc limit ${limit}`,
    types.length ? [types] : []
  );
  res.json(rows);
}));

app.get("/api/contacts", auth, wrap(async (req, res) => {
  const s = String(req.query.q || "").trim().replace(/^@/, "");
  const { rows } = await q(
    `select id, ig_id, username, tags, comments, first_seen, last_seen from contacts
     where $1 = '' or username ilike '%' || $1 || '%' or lower($1) = any(tags)
     order by last_seen desc limit 200`, [s]);
  res.json(rows);
}));

app.post("/api/contacts/:id/tags", auth, wrap(async (req, res) => {
  const add = (req.body.add || []).map(cleanTag).filter(Boolean);
  const remove = (req.body.remove || []).map(cleanTag).filter(Boolean);
  const { rows } = await q(
    `update contacts set tags = array(select distinct t from unnest(tags || $2::text[]) as t where t <> all($3::text[]) order by t)
     where id = $1 returning id, tags`, [req.params.id, add, remove]);
  rows[0] ? res.json(rows[0]) : res.sendStatus(404);
}));

// ---------- Início ----------
await initDb();
const cleanup = () => q("delete from events where at < now() - interval '30 days'").catch(() => {});
cleanup();
setInterval(cleanup, 24 * 3600 * 1000);
app.listen(PORT, () => console.log(`Rodando na porta ${PORT} | DRY_RUN=${DRY_RUN} | painel em /admin`));
