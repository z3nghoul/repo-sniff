// SYNTHETIC TEST FIXTURE — not functional
const { exec } = require("child_process");
const payload = "ZWNobyBoZWxsbyBmcm9tIHRoZSBzeW50aGV0aWMgZml4dHVyZTsgdGhpcyB0ZXh0IGlzIG5ldmVyIHJ1bi4gZWNobyBoZWxsbyBmcm9tIHRoZSBzeW50aGV0aWMgZml4dHVyZTsgdGhpcyB0ZXh0IGlzIG5ldmVyIHJ1bi4g";
exec(Buffer.from(payload, "base64").toString());
