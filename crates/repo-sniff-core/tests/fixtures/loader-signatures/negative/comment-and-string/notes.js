// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");
// eval(r.data) would be a bad idea; so would new Function(r.data)()
const help = "never call eval(response) on what axios.get returns";
/* eval(x); Function(x)(); */
axios.get("https://api.example.invalid/data").then((r) => JSON.parse(r.data));
module.exports = help;
