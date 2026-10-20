// Benchmark : flux de données sur plusieurs lignes et familles de failles récentes (vulnérable).
const express = require("express");
const axios = require("axios");
const _ = require("lodash");
const jwt = require("jsonwebtoken");
const { User } = require("./models");

const app = express();
app.use(express.json());

app.get("/greet", (req, res) => {
  const name = req.query.name;
  res.send("<h1>Bonjour " + name + "</h1>");
});

app.get("/avatar", async (req, res) => {
  const { url } = req.query;
  const image = await axios.get(url);
  res.type("png").send(image.data);
});

app.post("/login", async (req, res) => {
  const user = await User.findOne({ email: req.body.email, password: req.body.password });
  res.json({ ok: Boolean(user) });
});

app.post("/preferences", (req, res) => {
  const prefs = _.merge({}, req.body);
  res.json(prefs);
});

app.get("/me", (req, res) => {
  const claims = jwt.verify(req.headers.token, process.env.JWT_KEY, { algorithms: ["HS256", "none"] });
  res.json(claims);
});

app.get("/download", (req, res) => {
  const file = req.query.file;
  res.sendFile("/srv/files/" + file);
});

module.exports = app;
