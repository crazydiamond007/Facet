# Security policy

`facet` hands out a shell. A bug in its authentication is not an inconvenience. It is
remote code execution on someone's personal machine. Security reports are the most valuable
contribution you can make to this project, and they are always welcome.

## Reporting a vulnerability

**Please do not open a public issue for a security bug.**

Use GitHub's private reporting instead:
**[Report a vulnerability](https://github.com/crazydiamond007/Facet/security/advisories/new)**

I will acknowledge within a few days. Once there is a fix, I will credit you in the advisory
unless you would rather stay anonymous.

If you would rather not use GitHub, open a public issue that says only *"I have a security
report, how do I reach you"*, with no detail, and I will follow up.

## Scope

`facet` has had **no external security review**. It is an alpha personal project. Please
assume there are bugs and treat the threat model in the [README](README.md#threat-model) as a
statement of intent rather than a guarantee.

### In scope: I want to hear about these

- Anything that reaches a shell, or any authenticated endpoint, without valid credentials.
- Bypassing the TOTP second factor, replaying a code, or defeating the lockout.
- Forging, fixating or stealing a session cookie; anything that makes a JWT verify when it
  should not.
- Cross-site attacks that drive the terminal from another origin (CSRF, cross-site WebSocket
  hijacking, CSP escapes).
- Path traversal or information disclosure through the asset handler.
- Leaking secrets (the password hash, the TOTP seed, the JWT key) into logs, error
  responses, or the binary.
- Timing oracles that distinguish *which* credential was wrong.
- Anything that lets one terminal read or write another's I/O.

### Out of scope: these are working as designed

These are documented in the [threat model](README.md#threat-model), and are the deliberate
shape of the tool rather than bugs:

- **An authenticated user gets a full shell.** There is no sandbox and none is planned. That
  is the entire point of the program.
- **`logout` does not revoke the JWT.** The token is stateless and stays valid until it
  expires. Rotate `auth.jwt_secret` and restart to kill every session. (A *fix* for this,
  revocable sessions, is on the roadmap, and a PR would be welcome.)
- **An established WebSocket outlives token expiry.** The session is checked at upgrade, not
  continuously.
- **The lockout is global, not per-IP**, so someone who can reach the login page can lock the
  owner out for `lockout_minutes`. Per-IP lockout is worse (attackers rotate IPs); the real
  mitigation is not to expose the login page. See
  [Exposing it safely](README.md#exposing-it-safely).
- **The self-signed certificate from `facet setup` gives encryption, not identity.** It does
  not defend against an active man-in-the-middle. Use a real certificate or a tunnel.
- **Anyone who can read `facet.toml` can impersonate you.** It is written `chmod 600`;
  protecting it beyond that is the operating system's job.
- Denial of service by an *authenticated* user (they have a shell; they can just run
  `:(){ :|:& };:`).

## Supported versions

Alpha. Only the latest `main` is supported. There are no backports.
