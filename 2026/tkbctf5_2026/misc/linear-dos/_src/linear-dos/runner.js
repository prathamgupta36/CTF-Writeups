const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const readline = require("readline");

const FLAG = process.env.FLAG || "tkbctf{dummy}";
const CHALLENGE_PATH = path.join(__dirname, "challenge.js");
const NODE_PATH = process.execPath;

if (!fs.existsSync(CHALLENGE_PATH)) {
  throw new Error("challenge.js not found");
}

function ask(question, rl) {
  return new Promise((resolve) => rl.question(question, resolve));
}

(async () => {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const pattern = await ask("pattern > ", rl);
  const inputStr = await ask("input > ", rl);
  rl.close();

  if (pattern.length + inputStr.length > 1800) {
    throw new Error("Input lengths exceed the limit");
  }

  if ([...pattern, ...inputStr].some(x => x < " " || "\x80" <= x)) {
    throw new Error("Input contains invalid characters");
  }

  for (let i = 0; i < 3; i++) {
    console.log(`round ${i}:`);
    const result = spawnSync(
      NODE_PATH,
      [
        "--enable-experimental-regexp-engine",
        CHALLENGE_PATH,
        pattern,
        inputStr,
      ],
      {
        timeout: 2000,
        stdio: "inherit",
      }
    );

    if (result.error && result.error.code === "ETIMEDOUT") {
      continue;
    }

    process.exit(0);
  }

  console.log("Here is your flag:", FLAG);
})();
