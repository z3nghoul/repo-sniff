// SYNTHETIC TEST FIXTURE — not functional
const sources = { react: "/react.development.js" };

async function load() {
  const codes = await Promise.all(Object.values(sources).map((src) => fetch(src).then((res) => res.text())));
  codes.forEach((code) => {
    eval.call(window, code);
  });
}

load();
