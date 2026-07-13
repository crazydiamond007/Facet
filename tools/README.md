# tools

## build-font.mjs

Regenerates the vendored terminal font in `assets/vendor/fonts/`.

The font is **JetBrainsMono Nerd Font Mono**, subsetted. It is not a styling
choice: `starship` emits powerline separators and language symbols, `eza --icons`
puts a file-type glyph in front of every entry, and both arrive as ordinary
terminal output. A terminal that renders them as tofu boxes is failing to
reproduce its own output.

The glyph set is derived, not guessed:

* **eza's complete icon table**, extracted from `src/output/icons.rs` in eza's
  own source, so a file type nobody has opened yet still renders.
* **starship's symbols**, from `starship print-config`.
* **Powerline separators**, which prompt themes use even when the default config
  does not.
* **Box drawing, blocks, braille**, because `htop`, `lazygit`, `tmux` and every
  spinner in cargo and npm draw with them.

1,921 glyphs, 184 KB across two weights (400 and 700, the only ones anything
asks for). The icons account for ~45 KB per weight; they are detailed logo
outlines and there is no cheaper way to have them.

```bash
npm i subset-font
# fetch JetBrainsMono.zip from ryanoasis/nerd-fonts releases, extract the
# NerdFontMono TTFs into ./nf/, then:
node tools/build-font.mjs
```
