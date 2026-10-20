// Benchmark : entrée utilisateur transmise à des fonctions d'un autre fichier (vulnérable).
const express = require("express");
const { readUpload, fetchFeed } = require("./files");

const app = express();

app.get("/upload", async (req, res) => {
  const name = req.query.name;
  const content = await readUpload(name);
  res.type("text/plain").send(content);
});

app.get("/feed", async (req, res) => {
  res.json(await fetchFeed(req.query.url));
});

module.exports = app;
