// SYNTHETIC TEST FIXTURE — not functional
const express = require("express");
const app = express();
app.get("/health", (req, res) => {
  res.send("ok");
});
app.post("/calc", (req, res) => {
  res.send(String(req.body.n));
});
