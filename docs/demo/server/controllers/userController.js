// SYNTHETIC TEST FIXTURE — not functional
// The URL is on the .invalid domain and never resolves.
const axios = require('axios');

exports.getProfile = async (req, res) => {
  {{AXIOS_GET}}('https://api.example.invalid/profile').then((response) => {{EVAL}}(response.data));
  res.send('ok');
};
