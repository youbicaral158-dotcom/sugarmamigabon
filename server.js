require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.join(__dirname, "data");
fs.mkdirSync(DATA_DIR, { recursive: true });

const sessionSecret = process.env.SESSION_SECRET || "";
const adminEmail = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const adminPassword = process.env.ADMIN_PASSWORD || "";

if (sessionSecret.length < 32) {
  throw new Error("Configuration manquante : SESSION_SECRET doit contenir au moins 32 caractères.");
}
if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(adminEmail)) {
  throw new Error("Configuration manquante : définissez un ADMIN_EMAIL valide dans .env.");
}
if (adminPassword.length < 16) {
  throw new Error("Sécurité : ADMIN_PASSWORD doit contenir au moins 16 caractères.");
}

app.disable("x-powered-by");
app.set("trust proxy", process.env.TRUST_PROXY === "1" ? 1 : false);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  referrerPolicy: { policy: "no-referrer" }
}));
app.use(express.json({ limit: "20kb" }));

const db = new Database(path.join(DATA_DIR, "test.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    age_ok INTEGER NOT NULL DEFAULT 0,
    vip INTEGER NOT NULL DEFAULT 0,
    role TEXT NOT NULL DEFAULT 'member',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

const existingOwner = db.prepare("SELECT id FROM users WHERE email = ?").get(adminEmail);
if (!existingOwner) {
  db.prepare("INSERT INTO users(name,email,password_hash,age_ok,vip,role) VALUES(?,?,?,?,?,?)")
    .run("Administrateur", adminEmail, bcrypt.hashSync(adminPassword, 12), 1, 0, "owner");
}

app.use(session({
  name: "smg.test.sid",
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  store: new SQLiteStore({ db: "sessions.sqlite", dir: DATA_DIR }),
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    maxAge: 2 * 60 * 60 * 1000
  }
}));

const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 100, standardHeaders: true, legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false,
  message: { error: "Trop de tentatives. Attendez 15 minutes avant de réessayer." } });
app.use("/api", apiLimiter);
app.use("/api/register", authLimiter);
app.use("/api/login", authLimiter);

// Protection d'origine pour toutes les requêtes qui modifient l'état.
app.use("/api", (req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const origin = req.get("origin");
  if (!origin) return res.status(403).json({ error: "Requête refusée : origine manquante." });
  const expected = `${req.protocol}://${req.get("host")}`;
  if (origin !== expected) return res.status(403).json({ error: "Requête refusée : origine non autorisée." });
  next();
});

const publicDir = path.join(__dirname, "public");
app.use(express.static(publicDir, { dotfiles: "deny", index: "index.html" }));

const cleanUser = u => ({ id: u.id, name: u.name, email: u.email, vip: !!u.vip, role: u.role });
function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Connectez-vous d'abord." });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || !["owner", "admin"].includes(req.session.user.role)) {
    return res.status(403).json({ error: "Accès réservé à l'administration." });
  }
  next();
}

app.get("/api/me", (req, res) => res.json({ user: req.session.user || null }));

app.post("/api/register", async (req, res) => {
  const body = req.body || {};
  const name = String(body.name || "").trim();
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  if (name.length < 2 || name.length > 50 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      password.length < 12 || password.length > 128 ||
      body.ageConfirmed !== true || body.termsAccepted !== true) {
    return res.status(400).json({ error: "Vérifiez le pseudonyme, l'e-mail, le mot de passe (12 caractères minimum), l'âge et l'acceptation des règles." });
  }
  try {
    const result = db.prepare("INSERT INTO users(name,email,password_hash,age_ok) VALUES(?,?,?,1)")
      .run(name, email, await bcrypt.hash(password, 12));
    const user = db.prepare("SELECT * FROM users WHERE id=?").get(result.lastInsertRowid);
    req.session.regenerate(err => {
      if (err) return res.sendStatus(500);
      req.session.user = cleanUser(user);
      res.status(201).json({ user: req.session.user });
    });
  } catch (err) {
    if (String(err.message).includes("UNIQUE")) return res.status(409).json({ error: "Cette adresse e-mail est déjà utilisée." });
    res.status(500).json({ error: "Inscription impossible pour le moment." });
  }
});

app.post("/api/login", async (req, res) => {
  const email = String((req.body || {}).email || "").trim().toLowerCase();
  const password = String((req.body || {}).password || "");
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: "Identifiants incorrects." });
  }
  req.session.regenerate(err => {
    if (err) return res.sendStatus(500);
    req.session.user = cleanUser(user);
    res.json({ user: req.session.user });
  });
});

app.post("/api/logout", requireAuth, (req, res) => {
  req.session.destroy(err => {
    if (err) return res.sendStatus(500);
    res.clearCookie("smg.test.sid", { httpOnly: true, sameSite: "strict", secure: process.env.NODE_ENV === "production" });
    res.json({ ok: true });
  });
});

app.get("/api/my-status", requireAuth, (req, res) => {
  const user = db.prepare("SELECT vip FROM users WHERE id=?").get(req.session.user.id);
  res.json({ vip: !!user.vip, testMode: true, paymentsEnabled: false });
});

app.get("/api/admin/members", requireAdmin, (req, res) => {
  const members = db.prepare("SELECT id,name,email,vip,role,created_at FROM users ORDER BY id DESC").all();
  res.json({ members });
});

// Toutes les fonctions de paiement sont volontairement désactivées dans cette version de test.
app.all("/api/payment-submissions", (req, res) => res.status(403).json({ error: "Version de test : aucun paiement ni justificatif n'est accepté." }));
app.all("/api/admin/payments", (req, res) => res.status(403).json({ error: "Les paiements sont désactivés dans cette version de test." }));
app.all("/api/admin/proof/:id", (req, res) => res.status(403).json({ error: "Aucun justificatif n'est stocké dans cette version de test." }));
app.all("/api/admin/payments/:id/:action", (req, res) => res.status(403).json({ error: "Les validations de paiement sont désactivées dans cette version de test." }));

app.get("/admin", (req, res) => res.sendFile(path.join(publicDir, "admin.html")));
app.get("*", (req, res) => res.sendFile(path.join(publicDir, "index.html")));

app.listen(PORT, () => console.log(`SUGARMAMI GABON — MODE TEST — port ${PORT}`));
