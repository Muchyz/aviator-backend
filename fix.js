const fs = require('fs');

// Read current broken file
let code = fs.readFileSync('server.js', 'utf8');

// Find where real code starts (require/const lines)
const requireIdx = code.indexOf("require(\"dotenv\")");
const adminIdx = code.indexOf("// \u2500\u2500\u2500 ADMIN MIDDLEWARE");

if (requireIdx === -1) {
  console.log("Cannot find require block. File too broken.");
  process.exit(1);
}

// Extract: everything from require to end, remove duplicate admin section
let main = code.substring(requireIdx);

// Find START block
const startIdx = main.indexOf("// \u2500\u2500\u2500 START");
const adminInMain = main.indexOf("// \u2500\u2500\u2500 ADMIN MIDDLEWARE");

if (adminInMain !== -1 && adminInMain > startIdx) {
  // Admin is already after START - just need to swap
  const before = main.substring(0, startIdx);
  const startBlock = main.substring(startIdx, adminInMain);
  const adminBlock = main.substring(adminInMain);
  main = before + adminBlock.trimEnd() + "\n\n" + startBlock.trimEnd() + "\n";
} else {
  console.log("startIdx=" + startIdx + " adminInMain=" + adminInMain);
}

fs.writeFileSync('server.js', main);
console.log("Done! File starts with: " + main.substring(0,50));
