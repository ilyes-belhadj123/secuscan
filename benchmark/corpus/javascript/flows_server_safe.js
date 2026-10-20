// Benchmark : mêmes fonctionnalités que flows_server.js, écrites de façon sûre (aucune alerte attendue).
const path = require("path");
const express = require("express");
const axios = require("axios");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const escapeHtml = require("escape-html");
const { User } = require("./models");

const app = express();
app.use(express.json());

app.get("/greet", (req, res) => {
  const name = req.query.name;
  res.send("<h1>Bonjour " + escapeHtml(name) + "</h1>");
});

app.get("/avatar", async (req, res) => {
  const { id } = req.query;
  const image = await axios.get(`https://cdn.example.com/avatars/${encodeURIComponent(id)}.png`);
  res.type("png").send(image.data);
});

app.post("/login", async (req, res) => {
  const user = await User.findOne({ email: String(req.body.email) });
  const ok = Boolean(user) && (await bcrypt.compare(String(req.body.password), user.passwordHash));
  res.status(ok ? 200 : 401).json({ ok });
});

app.post("/preferences", (req, res) => {
  const prefs = { theme: String(req.body.theme), lang: String(req.body.lang) };
  res.json(prefs);
});

app.get("/me", (req, res) => {
  const claims = jwt.verify(req.headers.token, process.env.JWT_KEY, { algorithms: ["HS256"] });
  res.json(claims);
});

app.get("/download", (req, res) => {
  const file = req.query.file;
  res.sendFile(path.basename(file), { root: "/srv/files" });
});

module.exports = app;
