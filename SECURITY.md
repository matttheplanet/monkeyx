# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

If you find a security vulnerability *in MonkeyX itself* (the scanning engine,
its modules, the local web viewer, or the installer), report it privately:

Use GitHub's private vulnerability reporting — the **"Report a vulnerability"**
button under this repository's **Security** tab. This opens a private advisory
visible only to the maintainers, and is the preferred and supported channel for
all security reports.

Please include:

- a description of the issue and its impact,
- the version / commit you tested,
- clear steps to reproduce (a proof of concept if you have one),
- any suggested remediation.

We will acknowledge your report, keep you updated on our assessment, and
coordinate a fix and disclosure timeline with you. Please give us reasonable
time to remediate before any public disclosure.

## What is in scope

This policy covers defects in **MonkeyX as software**, for example:

- injection or command execution reachable through MonkeyX's own inputs
  (CLI arguments, config files, workflow/plugin definitions, the web viewer),
- authentication/authorization flaws or data exposure in the local web viewer,
- unsafe handling of scan output or credentials,
- supply-chain issues in MonkeyX's dependencies or installer.

## What is *not* a MonkeyX vulnerability

MonkeyX is an offensive-security tool. The following are **not** vulnerabilities
in this project:

- Findings that MonkeyX reports about **your targets** — those are issues in the
  scanned systems, not in MonkeyX. Report them to the system owner.
- Behavior that only occurs when the tool is pointed at systems the operator was
  **not authorized** to test. Authorization is the operator's responsibility (see
  [Responsible use](README.md#responsible-use)); misuse is out of scope.
- The tool being "too effective" (fast, parallel, noisy) when used as designed.

## Supported versions

MonkeyX is under active pre-1.0 development. Security fixes are applied to the
latest release / the default branch. Older commits are not maintained — please
reproduce on the current version before reporting.

## Handling of scan data and AI egress

MonkeyX processes potentially sensitive engagement data. Operators should read
[docs/AI_DATA_HANDLING.md](docs/AI_DATA_HANDLING.md) for exactly what leaves the
host when AI modules are enabled, and prefer a local provider (Ollama) for
engagements where no scan data may leave the network.
