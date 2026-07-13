// The error banner ships with the literal placeholder in it. The server swaps
// that for a real message only when there is one, so an unreplaced placeholder
// means "no error" and the banner stays hidden.
"use strict";

const banner = document.querySelector(".error");
if (banner && banner.textContent.trim() !== "__ERROR__") {
  banner.hidden = false;
}

// Six digits is always the whole code, so submit as soon as we have them
// rather than making the user reach for Enter while the code ticks over.
const code = document.getElementById("code");
const form = document.querySelector("form");

code?.addEventListener("input", () => {
  code.value = code.value.replace(/\D/g, "").slice(0, 6);
  if (code.value.length === 6 && form.password.value) {
    form.requestSubmit();
  }
});
