// Acme Shop — serveur Node (démonstration volontairement vulnérable)
const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const db = require("./db");

const app = express();
app.use(express.json());

// Clé factice codée en dur (mauvaise pratique volontaire)
const STRIPE_SECRET_KEY = "sk_test_DEMOFAKEKEY000000000000000";

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

app.get("/api/products", async (req, res) => {
  const category = req.query.category;
  const rows = await db.query(`SELECT * FROM products WHERE category = '${category}'`);
  res.json(rows);
});

app.get("/api/export", (req, res) => {
  const format = req.query.format;
  exec(`./scripts/export.sh ${format}`, (err, stdout) => {
    res.send(stdout);
  });
});

app.get("/api/docs", (req, res) => {
  res.sendFile(path.join(__dirname, "docs", req.query.page));
});

app.post("/api/pricing/rule", (req, res) => {
  const rule = eval(req.body.expression);
  res.json({ result: rule });
});

app.post("/api/checkout", async (req, res) => {
  const { productId, quantity, unitPrice } = req.body;
  const total = quantity * unitPrice;
  await db.query("INSERT INTO orders (product_id, quantity, total) VALUES ($1, $2, $3)", [productId, quantity, total]);
  res.json({ status: "paid", total });
});

app.listen(3000);
