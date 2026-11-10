# redacted

A small, browser-only tool for redacting logs and config files before you share them.
Paste text or drop a file. Sensitive values are replaced with consistent placeholders,
and you can review every change side by side before downloading `name.redacted.ext`.

**Nothing leaves your machine.** There's no server, no build step and no dependencies.
A strict Content-Security-Policy blocks all network connections.

## Run

Open `index.html` in a browser (double-clicking it works), or serve the folder:

```sh
python3 -m http.server 8000   # then open http://localhost:8000
```

`index.html#sample` loads a demo document.

## Features

- **Auto-detection**, each detector can be toggled:
  - **Network:** IPv4 (incl. CIDR), IPv6, MAC addresses, hostnames/FQDNs, `host=` / `server:` / `HostName` values
  - **Identity:** emails, usernames in home paths
  - **Secrets:**
    - `password=` / `secret:` / `token=` / `api_key` values
    - `Authorization: Bearer/Basic` values, JWTs
    - AWS keys; GitHub, Stripe, Slack, Google and GitLab tokens
    - credentials in URLs (`user:pass@`)
    - Kubernetes `env` secrets
    - PEM private keys
  - **Other:** UUIDs, Luhn-checked card numbers. Optional, off by default: high-entropy strings and hex hashes.
- **Consistent placeholders.** The same value always gets the same placeholder (`10.0.0.5 → <IP_1>`), so related log lines stay readable. The format is configurable (`<{TYPE}_{N}>`, `[{TYPE}-{N}]`, …).
- **Propagation.** Once a value is detected, every other occurrence is redacted too, e.g. a password that also appears in an error message. The short name `web01` is also redacted when `web01.corp.local` was found.
- **Side-by-side view.** Original and redacted text are aligned line by line. Hover a highlight to see its counterpart; click it for details or to stop redacting that value.
- **Manual control:**
  - Select text and click **Redact selection** to redact it everywhere.
  - Add literal **terms** (customer or company names).
  - Add **custom regex patterns**. A named group `(?<v>…)` redacts only part of a match.
  - Edit the **allowlist**, which supports `*` wildcards.
- **Export:**
  - **Download** (Ctrl+S) saves `app.log → app.redacted.log`; pasted text saves as `snippet.redacted.txt`.
  - **Copy** puts the redacted text on the clipboard.
  - **Mapping export** (JSON/CSV) lets you translate placeholders back. It contains the original values, so keep it private.
- **Profiles.** Settings are kept in the browser's localStorage. Export or import them as JSON to share rules with a team. Document content is never stored.
- Light and dark theme.

## Tests

Open `tests/tests.html` in a browser, or run it headless:

```sh
google-chrome --headless --dump-dom "file://$PWD/tests/tests.html" | grep -o 'id="summary"[^<]*'
```

`samples/` contains example files to try (nginx log, sshd_config, Kubernetes manifest, app log).

## Layout

| File | Purpose |
|------|---------|
| `js/rules.js` | detector definitions |
| `js/redactor.js` | engine: match → resolve overlaps → allowlist → propagate → number placeholders (no DOM) |
| `js/render.js` | side-by-side HTML renderer |
| `js/app.js` | UI wiring |

## Limitations and ideas

- Detection is pattern-based. Plain words (bare short hostnames, usernames like `alice`) are only caught via propagation or terms. Always review before sharing.
- Version strings such as `1.2.3.4` look like IPv4 addresses and will be redacted.
- Very large files (tens of MB) are processed on the main thread. A Web Worker and a virtualized grid would help.
- Ideas:
  - keep placeholder numbering consistent across several files in one session
  - batch redaction of multiple files into a zip
  - a Python CLI that shares the rule definitions
