// Build the vendored terminal font: JetBrainsMono Nerd Font Mono, subsetted to
// what a terminal actually draws.
//
//   - the latin/punctuation a shell prints
//   - box drawing, blocks, geometric shapes  (TUIs: htop, lazygit, tmux)
//   - braille                                (spinners: cargo, npm)
//   - the complete eza icon table + starship symbols + powerline separators
//
// The icon set is extracted from eza's own source and starship's default config
// rather than sampled from a directory listing, so a file type nobody has opened
// yet still renders instead of showing a tofu box.
import subsetFont from "subset-font";
import { readFile, writeFile } from "node:fs/promises";

const range = (a, b) => {
  let s = "";
  for (let c = a; c <= b; c++) s += String.fromCodePoint(c);
  return s;
};

const TERMINAL =
  range(0x0020, 0x00ff) + // latin-1
  range(0x2010, 0x203a) + // punctuation
  range(0x2190, 0x21ff) + // arrows
  range(0x2200, 0x22ff) + // math
  range(0x2500, 0x257f) + // box drawing
  range(0x2580, 0x259f) + // block elements
  range(0x25a0, 0x25ff) + // geometric shapes
  range(0x2600, 0x26ff) + // misc symbols
  range(0x2700, 0x27bf) + // dingbats
  range(0x2800, 0x28ff); // braille

const ICONS = await readFile("icons-complete.txt", "utf8");
const text = TERMINAL + ICONS;

const out = "/home/narcisse/programming/rust/Facet/assets/vendor/fonts";
const weights = { 400: "Regular", 700: "Bold" };

let total = 0;
for (const [weight, style] of Object.entries(weights)) {
  const ttf = await readFile(`nf/JetBrainsMonoNerdFontMono-${style}.ttf`);
  const woff2 = await subsetFont(ttf, text, { targetFormat: "woff2" });
  await writeFile(`${out}/jetbrains-mono-${weight}.woff2`, woff2);
  total += woff2.length;
  console.log(`  jetbrains-mono-${weight}.woff2   ${(woff2.length / 1024).toFixed(1).padStart(6)} KB`);
}

console.log(`  ${"".padEnd(28, "-")}`);
console.log(`  total                    ${(total / 1024).toFixed(1).padStart(6)} KB`);
console.log(`  glyphs                   ${new Set([...text]).size}`);
