// SYNTHETIC TEST FIXTURE — not functional
const body = "return 1;";
const make = new Function("require", body);
module.exports = make(require);
