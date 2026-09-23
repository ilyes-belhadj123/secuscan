// Corpus de benchmark SecuScan — code sûr (aucune alerte attendue)
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");
const { execFile } = require("child_process");
const db = require("./db");

const app = express();
app.use(express.json());
app.use(cors({ origin: ["https://app.example.com"] }));

const EXPORTS_DIR = path.resolve(__dirname, "exports");

app.get("/users/:id", async (req, res) => {
  const rows = await db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
  res.json(rows);
});

app.get("/git/log", (req, res) => {
  execFile("git", ["log", "--oneline", "--", String(req.query.branch)], (err, out) => res.send(out));
});

app.post("/pricing/formula", (req, res) => {
  const { a, b } = JSON.parse(req.body.operands);
  res.json({ value: Number(a) + Number(b) });
});

app.get("/download", (req, res) => {
  const target = path.resolve(EXPORTS_DIR, String(req.query.name));
  if (!target.startsWith(EXPORTS_DIR + path.sep)) return res.status(400).end();
  res.sendFile(target);
});

function newResetToken() {
  return crypto.randomUUID();
}

function animationDelay() {
  return 200 + Math.random() * 100;
}

module.exports = { app, newResetToken, animationDelay };
