// facet: the sign-in screen.
//
// The design shows two steps, password then authenticator code. The server
// takes both in a single POST, and that is not an accident: it evaluates the
// password and the code together so that a wrong password is not measurably
// faster than a wrong code. Splitting the request in two would hand an attacker
// exactly the oracle that design avoids.
//
// So the two steps here are an affordance, not two round trips. Step one
// collects the password and reveals step two; the form is submitted once, with
// both factors, when the code is complete.

"use strict";

const form = document.getElementById("form");
const password = document.getElementById("password");
const code = document.getElementById("code");
const cells = Array.from(document.querySelectorAll("#cells .cell"));

const stepPassword = document.getElementById("step-password");
const stepCode = document.getElementById("step-code");
const stepLocked = document.getElementById("step-locked");

const passwordError = document.getElementById("password-error");
const codeError = document.getElementById("code-error");

/** The server stamps the outcome onto <body>; we do not infer it from a message. */
const state = document.body.dataset.state;
const lockSeconds = Number(document.body.dataset.lockSeconds) || 0;

// ---------------------------------------------------------------------------
// Errors
//
// The banner ships with a literal placeholder in it. The server replaces it
// only when there is something to say, so an unreplaced placeholder means "no
// error" and the banner stays hidden.
// ---------------------------------------------------------------------------

const serverError =
  codeError && codeError.textContent.trim() !== "__ERROR__"
    ? codeError.textContent.trim()
    : "";

function show(step) {
  stepPassword.hidden = step !== "password";
  stepCode.hidden = step !== "code";
  stepLocked.hidden = step !== "locked";

  if (step === "password") password.focus();
  if (step === "code") code.focus();
}

// ---------------------------------------------------------------------------
// Step 1: password
// ---------------------------------------------------------------------------

function toCode() {
  if (!password.value) {
    passwordError.textContent = "password required";
    passwordError.hidden = false;
    password.focus();
    return;
  }
  passwordError.hidden = true;
  show("code");
}

document.getElementById("continue").addEventListener("click", toCode);

password.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    toCode();
  }
});

password.addEventListener("input", () => {
  passwordError.hidden = true;
});

// ---------------------------------------------------------------------------
// Step 2: the six cells
//
// They are drawn over a single real input. Six inputs would fight the password
// manager, break paste, and make backspace jump around; one input keeps the
// browser's own behaviour and lets the cells be pure presentation.
// ---------------------------------------------------------------------------

function paintCells() {
  const digits = code.value;
  cells.forEach((cell, index) => {
    cell.textContent = digits[index] ?? "";
    cell.classList.toggle("filled", index < digits.length);
    cell.classList.toggle(
      "active",
      index === digits.length && digits.length < cells.length,
    );
  });
}

document.getElementById("cells").addEventListener("click", () => code.focus());

code.addEventListener("input", () => {
  code.value = code.value.replace(/\D/g, "").slice(0, 6);
  codeError.hidden = true;
  paintCells();

  // Six digits is the whole code. Submit rather than make the user reach for
  // Enter while the 30-second window ticks over.
  if (code.value.length === 6) form.requestSubmit();
});

code.addEventListener("focus", paintCells);
code.addEventListener("blur", paintCells);

document.getElementById("back").addEventListener("click", () => {
  code.value = "";
  paintCells();
  show("password");
});

// ---------------------------------------------------------------------------
// Locked
// ---------------------------------------------------------------------------

function countdown(seconds) {
  const el = document.getElementById("countdown");
  let left = seconds;

  const paint = () => {
    if (left <= 0) {
      el.textContent = "you may try again";
      return;
    }
    const minutes = String(Math.floor(left / 60)).padStart(2, "0");
    const secs = String(left % 60).padStart(2, "0");
    el.textContent = `retry available in ${minutes}:${secs}`;
    left -= 1;
    setTimeout(paint, 1000);
  };

  paint();
}

document.getElementById("relogin").addEventListener("click", () => {
  // Reloading gets a fresh CSRF token; reusing this page's spent one would be
  // rejected and look like a second, mysterious failure.
  location.href = "/login";
});

// ---------------------------------------------------------------------------
// Transport, shown honestly
//
// The design's footer read "TLS 1.3 · AES-256-GCM". JavaScript cannot see the
// negotiated version or cipher, so printing them would be decoration that
// happens to look like a security claim. We show what we can actually check.
// ---------------------------------------------------------------------------

const secure = location.protocol === "https:";
const transport = document.getElementById("transport");
transport.textContent = secure ? "TLS" : "no TLS";
transport.classList.toggle("good", secure);
transport.classList.toggle("error", !secure);
document.getElementById("origin").textContent = location.host;

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

if (state === "locked") {
  show("locked");
  countdown(lockSeconds);
} else if (serverError) {
  // Back to step one, not step two. A rejected attempt re-renders the page with
  // an empty password field, so leaving the user on the code step would submit
  // a blank password and fail again, forever, for a reason they cannot see.
  // Both factors have to be re-entered, so ask for both.
  passwordError.textContent = serverError;
  passwordError.hidden = false;
  codeError.hidden = true;
  show("password");
} else {
  show("password");
}

paintCells();
