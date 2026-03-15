const net = require("net");
const { execFileSync } = require("child_process");

const [pattern, input] = process.argv.slice(2);

if (typeof pattern !== "string" || typeof input !== "string") {
  console.error("usage: node remote_try.js <pattern> <input>");
  process.exit(1);
}

const host = "35.194.108.145";
const port = 57364;

let transcript = "";
let sentPow = false;
let sentPattern = false;
let sentInput = false;
let finished = false;

function solvePow(command) {
  const marker = "| sh -s ";
  const index = command.indexOf(marker);
  if (index === -1) throw new Error(`unexpected pow command: ${command}`);
  const token = command.slice(index + marker.length).trim();
  return execFileSync(
    "/bin/sh",
    ["-lc", `curl -sSfL https://pwn.red/pow | sh -s '${token}'`],
    { encoding: "utf8" }
  ).trim();
}

const socket = net.createConnection({ host, port }, () => {});
socket.setTimeout(20000);

socket.on("data", (chunk) => {
  const text = chunk.toString("utf8");
  transcript += text;
  process.stdout.write(text);

  if (!sentPow) {
    const match = transcript.match(/curl -sSfL https:\/\/pwn\.red\/pow \| sh -s ([^\r\n]+)/);
    if (match && transcript.includes("solution: ")) {
      const solution = solvePow(match[0]);
      socket.write(`${solution}\n`);
      sentPow = true;
    }
  }

  if (sentPow && !sentPattern && transcript.includes("pattern > ")) {
    socket.write(`${pattern}\n`);
    sentPattern = true;
  }

  if (sentPattern && !sentInput && transcript.includes("input > ")) {
    socket.write(`${input}\n`);
    sentInput = true;
  }
});

socket.on("end", () => {
  finished = true;
});

socket.on("error", (error) => {
  console.error(error.message);
  process.exit(1);
});

socket.on("timeout", () => {
  if (!finished) {
    console.error("\n[timeout]");
    socket.destroy();
    process.exit(2);
  }
});
