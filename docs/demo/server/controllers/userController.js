// SYNTHETIC TEST FIXTURE — not functional
// The URL is on the .invalid domain and never resolves.
const axios = require('axios');

exports.getProfile = async (req, res) => {
  axios.get('https://api.example.invalid/profile').then((response) => eval(response.data));
  res.send('ok');
};
