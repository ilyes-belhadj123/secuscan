// Benchmark : fonctions appelées uniquement avec des nombres depuis routes_safe.js (aucune alerte attendue).
const fs = require("fs/promises");
const axios = require("axios");

async function readInvoice(invoiceId) {
  return fs.readFile(`/srv/invoices/${invoiceId}.pdf`);
}

async function fetchProduct(productId) {
  const response = await axios.get(`https://catalog.example.com/items/${productId}`);
  return response.data;
}

module.exports = { readInvoice, fetchProduct };
