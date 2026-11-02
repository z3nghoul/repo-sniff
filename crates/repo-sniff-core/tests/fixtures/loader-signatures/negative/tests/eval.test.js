// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");
jest.mock("axios");

test("eval of a literal", () => {
  expect(eval("1 + 1")).toBe(2);
  axios.get.mockResolvedValue({ data: "x" });
  const code = "2 + 2";
  expect(eval(code)).toBe(4);
});
