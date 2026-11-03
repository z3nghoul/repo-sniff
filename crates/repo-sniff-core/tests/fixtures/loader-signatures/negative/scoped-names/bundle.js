// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");

function download(url) {
  const content = {{AXIOS_GET}}(url);
  return content;
}

function compile(content) {
  return {{EVAL}}("(" + content + ")");
}

compile("1 + 1");
download("https://api.example.invalid/data");
