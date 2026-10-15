// Benign JavaScript with the shapes the pack must not fire on: a read of a file
// that is not a credential store, an environment lookup that is not a secret,
// and a log line that is not a dataset.
const fs = require("fs");
const path = require("path");

function load() {
  const text = fs.readFileSync(path.join(__dirname, "config", "app.json"), "utf8");
  const home = process.env.HOME;
  console.log("loaded %d bytes into %s", text.length, home);
}
