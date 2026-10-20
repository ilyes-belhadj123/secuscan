// Benchmark : fonctions appelées avec une entrée utilisateur depuis routes.js (vulnérable).
const fs = require("fs/promises");
const axios = require("axios");

async function readUpload(fileName) {
  return fs.readFile("/srv/uploads/" + fileName, "utf8");
}

async function fetchFeed(feedUrl) {
  const response = await axios.get(feedUrl);
  return response.data;
}

module.exports = { readUpload, fetchFeed };
