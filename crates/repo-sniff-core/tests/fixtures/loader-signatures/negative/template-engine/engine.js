// SYNTHETIC TEST FIXTURE — not functional
function compile(source) {
  const body = "return `" + source.replace(/`/g, "\\`") + "`;";
  return new {{FUNCTION}}("locals", body);
}
module.exports = { compile, render: (s, l) => compile(s)(l) };
