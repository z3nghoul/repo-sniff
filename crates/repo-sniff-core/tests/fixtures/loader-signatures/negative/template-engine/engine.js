// SYNTHETIC TEST FIXTURE — not functional
function compile(source) {
  const body = "return `" + source.replace(/`/g, "\\`") + "`;";
  return new Function("locals", body);
}
module.exports = { compile, render: (s, l) => compile(s)(l) };
