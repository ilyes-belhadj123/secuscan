// Benchmark : mêmes appels entre fichiers, avec des valeurs converties en nombres (aucune alerte attendue).
const express = require("express");
const { readInvoice, fetchProduct } = require("./files_safe");

const app = express();

app.get("/invoice", async (req, res) => {
  const content = await readInvoice(Number(req.query.id));
  res.type("application/pdf").send(content);
});

app.get("/product", async (req, res) => {
  res.json(await fetchProduct(parseInt(req.query.id, 10)));
});

module.exports = app;
