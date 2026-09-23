// Corpus de benchmark SecuScan — code volontairement vulnérable (ne pas déployer)
const express = require("express");
const cors = require("cors");
const fs = require("fs");
const { exec } = require("child_process");
const db = require("./db");

const app = express();
app.use(express.json());
app.use(cors({ origin: "*" }));

app.get("/users/:id", async (req, res) => {
  const rows = await db.query("SELECT * FROM users WHERE id = " + req.params.id);
  res.json(rows);
});

app.get("/orders", async (req, res) => {
  const sql = `SELECT * FROM orders WHERE customer = '${req.query.customer}'`;
  res.json(await db.query(sql));
});

app.get("/git/log", (req, res) => {
  exec("git log --oneline " + req.query.branch, (err, out) => res.send(out));
});

app.post("/pricing/formula", (req, res) => {
  res.json({ value: eval(req.body.formula) });
});

app.post("/pricing/rule", (req, res) => {
  const rule = new Function("price", "return " + req.body.rule);
  res.json({ value: rule(100) });
});

app.get("/search", (req, res) => {
  res.send("<h1>Résultats pour " + req.query.q + "</h1>");
});

app.get("/download", (req, res) => {
  fs.readFile("./exports/" + req.query.name, (err, data) => res.send(data));
});

app.get("/sso/callback", (req, res) => {
  res.redirect(req.query.returnTo);
});

function newResetToken() {
  return Math.random().toString(36).slice(2);
}

module.exports = { app, newResetToken };
