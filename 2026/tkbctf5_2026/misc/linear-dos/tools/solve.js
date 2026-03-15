const path = require("path");
const { spawn } = require("child_process");

const unit = "(((.*)+){8}((.*)+){8})";
const repeat = 56;
const pattern = unit.repeat(repeat) + "X";
const input = "a".repeat(1800 - pattern.length);

const child = spawn(
  process.execPath,
  [path.join(__dirname, "remote_try.js"), pattern, input],
  { stdio: "inherit" }
);

child.on("exit", (code) => process.exit(code ?? 0));
