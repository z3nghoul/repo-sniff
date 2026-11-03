// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");
// {{EVAL}}(r.data) would be a bad idea; so would new {{FUNCTION}}(r.data)()
const help = "never call {{EVAL}}(response) on what axios.get returns";
/* {{EVAL}}(x); {{FUNCTION}}(x)(); */
axios.get("https://api.example.invalid/data").then((r) => JSON.parse(r.data));
module.exports = help;
