# gptel-oauth

> **⚠️ Warning:** Use at your own risk. We cannot guarantee that the use of this package is compliant with Anthropic's or OpenAI's Terms of Service.

OAuth (PKCE) authentication backends for [gptel](https://github.com/karthink/gptel), enabling access to:

- **Claude** (Anthropic) via a **Claude Pro/Max** subscription — no API key needed
- **OpenAI Codex** via a **ChatGPT Plus/Pro** subscription — using the Codex CLI Responses API

Credentials are persisted to disk and automatically refreshed before each request.

---

## Requirements

- Emacs 28.1+
- [gptel](https://github.com/karthink/gptel) 0.9.0+

---

## Installation

### Manual

Clone this repository and add it to your `load-path`:

```emacs-lisp
(add-to-list 'load-path "/path/to/gptel-oauth")
(require 'gptel-oauth)
```

### use-package (straight.el)

```emacs-lisp
(use-package gptel-oauth
  :straight (:host github :repo "colobas/gptel-oauth")
  :after gptel)
```

---

## Usage

### Anthropic (Claude Pro/Max)

**1. Log in once:**

```
M-x gptel-oauth-login-anthropic
```

This opens a browser to `claude.ai`. After authorizing, paste the authorization code (or the full redirect URL) back into the Emacs minibuffer.

**2. Create a backend:**

<!-- @models.dev:anthropic -->
```emacs-lisp
(gptel-make-anthropic-oauth "Claude-OAuth"
  :stream t
  :models '(claude-sonnet-4-6 claude-opus-4-6))
```
<!-- @/models.dev:anthropic -->

---

### OpenAI Codex (ChatGPT Plus/Pro)

**1. Log in once:**

```
M-x gptel-oauth-login-codex
```

This opens a browser to `auth.openai.com`. A local HTTP server is started on port `1455` to capture the OAuth callback automatically. If the port is unavailable, you will be prompted to paste the redirect URL manually.

**2. Create a backend:**

```emacs-lisp
(gptel-make-codex "Codex"
  :stream t
  :models '(codex-mini-latest gpt-4o))
```

#### Available Codex models

<!-- @models.dev:openai-codex -->
| Model | Description |
|---|---|
| `gpt-5.3-codex` | GPT-5.3 Codex |
| `gpt-5.3-codex-spark` | GPT-5.3 Codex Spark |
| `gpt-5.2-codex` | GPT-5.2 Codex |
| `gpt-5.1-codex-max` | GPT-5.1 Codex Max |
| `gpt-5.1-codex-mini` | GPT-5.1 Codex mini |
| `gpt-5.1-codex` | GPT-5.1 Codex |
| `gpt-5-codex` | GPT-5-Codex |
| `codex-mini-latest` | Codex Mini |
<!-- @/models.dev:openai-codex -->

---

## Logging out

```
M-x gptel-oauth-logout
```

You will be prompted to choose a provider (`anthropic`, `codex`, or `all`). This removes the stored credentials from disk.

---

## Credential storage

Credentials (access token, refresh token, expiry) are stored in:

```
~/.config/gptel/oauth-credentials.json
```

The path respects `$XDG_CONFIG_HOME` if set. It can be customized via:

```emacs-lisp
(setq gptel-oauth-credentials-file "/your/custom/path/oauth-credentials.json")
```

Tokens are automatically refreshed 5 minutes before expiry.

---

## How it works

Both flows use **OAuth 2.0 with PKCE** (Proof Key for Code Exchange):

- **Anthropic**: redirects to `console.anthropic.com` after login; you paste the `code#state` or full redirect URL back into Emacs.
- **Codex**: redirects to `localhost:1455/auth/callback`; `gptel-oauth` spins up a temporary local HTTP server to capture the code automatically, then shuts it down.

---

## License

MIT
