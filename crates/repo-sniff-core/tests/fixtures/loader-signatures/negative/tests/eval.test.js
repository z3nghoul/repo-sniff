// SYNTHETIC TEST FIXTURE — not functional
const axios = require("axios");
jest.mock("axios");

test("{{EVAL}} of a literal", () => {
  expect({{EVAL}}("1 + 1")).toBe(2);
  {{AXIOS_GET}}.mockResolvedValue({ data: "x" });
  const code = "2 + 2";
  expect({{EVAL}}(code)).toBe(4);
});
