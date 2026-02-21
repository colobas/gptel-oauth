;;; gptel-oauth.el --- OAuth authentication for gptel  -*- lexical-binding: t; -*-

;; Copyright (C) 2026 Guilherme Pires

;; Version: 0.1.0
;; Package-Requires: ((emacs "28.1") (gptel "0.9.0"))
;; Keywords: convenience, tools
;; URL: https://github.com/colobas/gptel-oauth

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; This file provides OAuth (PKCE) authentication for two gptel backends:
;;
;; 1. Claude (Anthropic) via Claude Pro/Max subscription:
;;
;;    (gptel-oauth-login-anthropic)  ; one-time login
;;    (gptel-make-anthropic-oauth "Claude-OAuth"
;;      :stream t
;;      :models '(claude-opus-4-5-20251101 claude-sonnet-4-5-20250929))
;;
;; 2. OpenAI Codex (ChatGPT Plus/Pro) via Codex CLI subscription:
;;
;;    (gptel-oauth-login-codex)      ; one-time login (starts local server on :1455)
;;    (gptel-make-codex "Codex"
;;      :stream t
;;      :models '(codex-mini-latest gpt-4o))
;;
;; Credentials are persisted to `gptel-oauth-credentials-file' and
;; auto-refreshed before each request.  Call `gptel-oauth-login-anthropic'
;; or `gptel-oauth-login-codex' again to re-authenticate.

;;; Code:

(require 'cl-generic)
(require 'cl-lib)
(require 'json)
(require 'url)
(require 'url-http)
(require 'url-util)
(require 'map)
(require 'gptel)
(require 'gptel-openai)
(require 'gptel-anthropic)

(declare-function gptel--json-read "gptel-openai")
(declare-function gptel--json-read-string "gptel-openai")
(declare-function gptel--json-encode "gptel-openai")
(declare-function gptel--process-models "gptel-openai")
(declare-function gptel-context--collect-media "gptel-context")

(defvar url-http-end-of-headers)

;; ============================================================================
;; Customization
;; ============================================================================

(defgroup gptel-oauth nil
  "OAuth authentication for gptel."
  :group 'gptel
  :prefix "gptel-oauth-")

(defcustom gptel-oauth-credentials-file
  (expand-file-name "oauth-credentials.json"
                    (or (and (getenv "XDG_CONFIG_HOME")
                             (expand-file-name "gptel" (getenv "XDG_CONFIG_HOME")))
                        (expand-file-name "gptel" (expand-file-name ".config" "~"))))
  "File path for storing OAuth credentials.
The file holds refresh and access tokens for all OAuth providers."
  :type 'file
  :group 'gptel-oauth)

;; ============================================================================
;; Internal variables
;; ============================================================================

(defvar gptel-oauth--credentials nil
  "In-memory credential store.
An alist mapping provider-id strings to credential plists.
Each plist has at minimum: :access :refresh :expires.
Codex credentials additionally include :account-id.")

(defvar gptel-oauth--callback-server nil
  "Network process for the local OAuth callback server (port 1455).")

(defvar gptel-oauth--callback-code nil
  "Auth code captured by the local OAuth callback server.")

;; ============================================================================
;; PKCE utilities
;; ============================================================================

(defun gptel-oauth--base64url-encode (bytes)
  "Encode unibyte string BYTES as base64url (no padding)."
  (thread-last (base64-encode-string bytes t)
               (replace-regexp-in-string "+" "-")
               (replace-regexp-in-string "/" "_")
               (replace-regexp-in-string "=" "")))

(defun gptel-oauth--generate-pkce ()
  "Generate a PKCE verifier/challenge pair.
Returns a cons cell (VERIFIER . CHALLENGE) using 32 random bytes."
  (let* ((raw (apply #'unibyte-string
                     (cl-loop repeat 32 collect (random 256))))
         (verifier  (gptel-oauth--base64url-encode raw))
         (challenge (gptel-oauth--base64url-encode
                     (secure-hash 'sha256 verifier nil nil t))))
    (cons verifier challenge)))

;; ============================================================================
;; Credential storage
;; ============================================================================

(defun gptel-oauth--load-credentials ()
  "Load credentials from `gptel-oauth-credentials-file' into memory."
  (setq gptel-oauth--credentials nil)
  (when (file-readable-p gptel-oauth-credentials-file)
    (condition-case err
        (with-temp-buffer
          (insert-file-contents gptel-oauth-credentials-file)
          (unless (string-blank-p (buffer-string))
            ;; Parse JSON object into alist of (provider-id . plist)
            (setq gptel-oauth--credentials
                  (let* ((json-object-type 'alist)
                         (json-array-type  'list)
                         (json-key-type    'string)
                         (obj (json-read-from-string (buffer-string))))
                    (mapcar (lambda (pair)
                              (cons (car pair)
                                    (let* ((json-object-type 'plist)
                                           (json-key-type    'keyword))
                                      (json-read-from-string
                                       (json-encode (cdr pair))))))
                            obj)))))
      (error
       (message "gptel-oauth: Failed to load credentials: %s"
                (error-message-string err))))))

(defun gptel-oauth--save-credentials ()
  "Persist in-memory credentials to `gptel-oauth-credentials-file'."
  (make-directory (file-name-directory gptel-oauth-credentials-file) t)
  (let* ((obj (cl-loop for (id . creds) in gptel-oauth--credentials
                       collect (cons id
                                     ;; plist -> alist for JSON
                                     (cl-loop for (k v) on creds by #'cddr
                                              collect (cons (substring (symbol-name k) 1)
                                                            v))))))
    (with-temp-file gptel-oauth-credentials-file
      (insert (json-encode obj))
      (insert "\n"))))

(defun gptel-oauth--get-credentials (provider-id)
  "Return credentials plist for PROVIDER-ID, or nil."
  (unless gptel-oauth--credentials
    (gptel-oauth--load-credentials))
  (cdr (assoc provider-id gptel-oauth--credentials)))

(defun gptel-oauth--set-credentials (provider-id creds)
  "Store CREDS plist under PROVIDER-ID and save to disk."
  (unless gptel-oauth--credentials
    (gptel-oauth--load-credentials))
  (if-let* ((pair (assoc provider-id gptel-oauth--credentials)))
      (setcdr pair creds)
    (push (cons provider-id creds) gptel-oauth--credentials))
  (gptel-oauth--save-credentials))

(defun gptel-oauth--delete-credentials (provider-id)
  "Remove credentials for PROVIDER-ID from memory and disk."
  (setq gptel-oauth--credentials
        (cl-delete provider-id gptel-oauth--credentials
                   :key #'car :test #'equal))
  (gptel-oauth--save-credentials))

;; ============================================================================
;; HTTP POST helper
;; ============================================================================

(defun gptel-oauth--http-post (url body &optional json-p)
  "Synchronously POST to URL with BODY, return parsed JSON plist.
If JSON-P is non-nil, send BODY as JSON; otherwise as
application/x-www-form-urlencoded.  Signals an error on HTTP failure."
  (let* ((url-request-method "POST")
         (url-request-extra-headers
          `(("Content-Type" . ,(if json-p
                                   "application/json"
                                 "application/x-www-form-urlencoded"))))
         (url-request-data
          (encode-coding-string
           (if json-p (json-encode body)
             (url-build-query-string
              (cl-loop for (k . v) in body collect (list k v))))
           'utf-8))
         buf status)
    (setq buf (url-retrieve-synchronously url 'silent nil 30))
    (unless buf
      (error "gptel-oauth: No response from %s" url))
    (with-current-buffer buf
      (goto-char (point-min))
      (when (re-search-forward "HTTP/[0-9.]+ \\([0-9]+\\)" nil t)
        (setq status (string-to-number (match-string 1))))
      (goto-char url-http-end-of-headers)
      (let* ((json-object-type 'plist)
             (json-key-type    'keyword)
             (body-str (buffer-substring-no-properties (point) (point-max)))
             (parsed (condition-case nil
                         (json-read-from-string body-str)
                       (error nil))))
        (kill-buffer buf)
        (unless (and status (>= status 200) (< status 300))
          (let ((err-msg (or (and parsed (plist-get parsed :error_description))
                             (and parsed (plist-get parsed :error))
                             body-str)))
            (error "gptel-oauth: HTTP %s from %s: %s" status url err-msg)))
        parsed))))

;; ============================================================================
;; Local OAuth callback server (for OpenAI Codex)
;; ============================================================================

(defconst gptel-oauth--callback-success-html
  "<html><head><title>Authentication successful</title></head>\
<body><p>Authentication successful. You may return to Emacs.</p></body></html>"
  "HTML sent to the browser after a successful OAuth callback.")

(defun gptel-oauth--callback-filter (proc data expected-state)
  "Network process filter that captures the OAuth code from DATA.
PROC is the client connection process.  EXPECTED-STATE is the PKCE state."
  (when (string-match "GET /auth/callback\\?\\([^ \t\n\r]*\\)" data)
    (let* ((query  (match-string 1 data))
           (params (url-parse-query-string query))
           (code   (cadr (assoc "code"  params)))
           (state  (cadr (assoc "state" params))))
      (when (and code (equal state expected-state))
        (process-send-string
         proc
         (concat "HTTP/1.1 200 OK\r\n"
                 "Content-Type: text/html\r\n"
                 "Connection: close\r\n\r\n"
                 gptel-oauth--callback-success-html))
        (setq gptel-oauth--callback-code code)
        ;; Give browser time to receive the response, then close
        (run-at-time 0.5 nil (lambda ()
                               (ignore-errors (delete-process proc))
                               (gptel-oauth--stop-callback-server)))))))

(defun gptel-oauth--start-callback-server (expected-state)
  "Start a local HTTP server on 127.0.0.1:1455 to capture the OAuth code.
EXPECTED-STATE is the PKCE state string used to validate the callback.
Returns non-nil on success, nil if the port is busy."
  (gptel-oauth--stop-callback-server)
  (setq gptel-oauth--callback-code nil)
  (condition-case err
      (let ((server
             (make-network-process
              :name     "gptel-oauth-server"
              :server   t
              :host     "127.0.0.1"
              :service  1455
              :family   'ipv4
              :filter   (lambda (proc data)
                          (gptel-oauth--callback-filter proc data expected-state))
              :sentinel (lambda (_proc _event) nil))))
        (setq gptel-oauth--callback-server server)
        t)
    (error
     (message "gptel-oauth: Could not start callback server on :1455: %s; \
falling back to manual code entry." (error-message-string err))
     nil)))

(defun gptel-oauth--stop-callback-server ()
  "Shut down the local OAuth callback server."
  (when (and gptel-oauth--callback-server
             (process-live-p gptel-oauth--callback-server))
    (delete-process gptel-oauth--callback-server))
  (setq gptel-oauth--callback-server nil))

(defun gptel-oauth--wait-for-callback (timeout-secs)
  "Poll for up to TIMEOUT-SECS seconds for the OAuth callback code.
Returns the code string, or nil on timeout."
  (cl-loop
   with deadline = (+ (float-time) timeout-secs)
   while (and (null gptel-oauth--callback-code)
              (< (float-time) deadline)
              (or (null gptel-oauth--callback-server)
                  (process-live-p gptel-oauth--callback-server)))
   do (accept-process-output nil 0.2)
   finally return gptel-oauth--callback-code))

;; ============================================================================
;; JWT helper (for Codex account-id extraction)
;; ============================================================================

(defun gptel-oauth--decode-jwt-payload (token)
  "Return the JSON payload plist of JWT TOKEN, or nil on failure."
  (condition-case nil
      (let ((parts (split-string token "\\.")))
        (when (= (length parts) 3)
          (let* ((raw (nth 1 parts))
                 ;; JWT uses base64url; add padding and decode
                 (padded (concat raw (make-string (mod (- 4 (mod (length raw) 4)) 4) ?=)))
                 (decoded (base64-decode-string
                           (replace-regexp-in-string
                            "_" "/" (replace-regexp-in-string "-" "+" padded))))
                 (json-object-type 'plist)
                 (json-key-type    'keyword))
            (json-read-from-string decoded))))
    (error nil)))

(defun gptel-oauth--codex-account-id (access-token)
  "Extract the ChatGPT account ID from Codex ACCESS-TOKEN JWT.
Returns the account-id string, or signals an error."
  (let* ((payload  (gptel-oauth--decode-jwt-payload access-token))
         (auth     (plist-get payload
                              (intern ":https://api.openai.com/auth")))
         (acct-id  (and auth (plist-get auth :chatgpt_account_id))))
    (or acct-id
        (error "gptel-oauth: Could not extract account ID from Codex token"))))

;; ============================================================================
;; Anthropic OAuth constants and flow
;; ============================================================================

(defconst gptel-oauth--anthropic-client-id
  ;; base64-decoded from "OWQxYzI1MGEtZTYxYi00NGQ5LTg4ZWQtNTk0NGQxOTYyZjVl"
  (base64-decode-string "OWQxYzI1MGEtZTYxYi00NGQ5LTg4ZWQtNTk0NGQxOTYyZjVl")
  "Anthropic OAuth client ID for Claude Pro/Max.")

(defconst gptel-oauth--anthropic-authorize-url
  "https://claude.ai/oauth/authorize"
  "Anthropic OAuth authorization endpoint.")

(defconst gptel-oauth--anthropic-token-url
  "https://console.anthropic.com/v1/oauth/token"
  "Anthropic OAuth token endpoint.")

(defconst gptel-oauth--anthropic-redirect-uri
  "https://console.anthropic.com/oauth/code/callback"
  "Anthropic OAuth redirect URI.")

(defconst gptel-oauth--anthropic-scopes
  "org:create_api_key user:profile user:inference"
  "Requested scopes for Anthropic OAuth.")

(defun gptel-oauth--anthropic-do-login ()
  "Run the Anthropic OAuth PKCE flow.
Opens a browser window and prompts for the authorization code.
Returns a credentials plist with :access :refresh :expires."
  (let* ((pkce      (gptel-oauth--generate-pkce))
         (verifier  (car pkce))
         (challenge (cdr pkce))
         (params    (url-build-query-string
                     `(("code"                  "true")
                       ("client_id"             ,gptel-oauth--anthropic-client-id)
                       ("response_type"         "code")
                       ("redirect_uri"          ,gptel-oauth--anthropic-redirect-uri)
                       ("scope"                 ,gptel-oauth--anthropic-scopes)
                       ("code_challenge"        ,challenge)
                       ("code_challenge_method" "S256")
                       ("state"                 ,verifier))))
         (auth-url  (concat gptel-oauth--anthropic-authorize-url "?" params)))

    ;; Open browser
    (message "gptel-oauth: Opening browser for Anthropic authentication...")
    (browse-url auth-url)

    ;; Prompt for code#state (Anthropic redirects to console.anthropic.com, no local server)
    (let* ((raw   (read-string
                   (concat "Paste the authorization code from the browser\n"
                           "(format: CODE#STATE or full redirect URL): ")))
           (code  (if (string-match "code=\\([^&#]+\\)" raw)
                      (match-string 1 raw)
                    (car (split-string (string-trim raw) "#"))))
           (state (if (string-match "state=\\([^&#]+\\)" raw)
                      (match-string 1 raw)
                    (cadr (split-string (string-trim raw) "#")))))

      ;; Exchange code for tokens
      (message "gptel-oauth: Exchanging authorization code for tokens...")
      (let* ((resp (gptel-oauth--http-post
                    gptel-oauth--anthropic-token-url
                    `(("grant_type"    . "authorization_code")
                      ("client_id"     . ,gptel-oauth--anthropic-client-id)
                      ("code"          . ,code)
                      ("state"         . ,(or state verifier))
                      ("redirect_uri"  . ,gptel-oauth--anthropic-redirect-uri)
                      ("code_verifier" . ,verifier))
                    'json))
             (access     (plist-get resp :access_token))
             (refresh    (plist-get resp :refresh_token))
             (expires-in (plist-get resp :expires_in)))
        (unless (and access refresh)
          (error "gptel-oauth: Anthropic token exchange failed: %S" resp))
        (list :access  access
              :refresh refresh
              ;; Subtract 5 min buffer; expires_in is in seconds, we store ms
              :expires (+ (* (float-time) 1000)
                          (* (- expires-in 300) 1000)))))))

(defun gptel-oauth--anthropic-refresh (refresh-token)
  "Refresh the Anthropic OAuth token using REFRESH-TOKEN.
Returns an updated credentials plist."
  (let* ((resp (gptel-oauth--http-post
                gptel-oauth--anthropic-token-url
                `(("grant_type"    . "refresh_token")
                  ("client_id"     . ,gptel-oauth--anthropic-client-id)
                  ("refresh_token" . ,refresh-token))
                'json))
         (access     (plist-get resp :access_token))
         (refresh    (plist-get resp :refresh_token))
         (expires-in (plist-get resp :expires_in)))
    (unless (and access refresh)
      (error "gptel-oauth: Anthropic token refresh failed: %S" resp))
    (list :access  access
          :refresh refresh
          :expires (+ (* (float-time) 1000)
                      (* (- expires-in 300) 1000)))))

;; ============================================================================
;; OpenAI Codex OAuth constants and flow
;; ============================================================================

(defconst gptel-oauth--codex-client-id
  "app_EMoamEEZ73f0CkXaXp7hrann"
  "OpenAI Codex OAuth client ID.")

(defconst gptel-oauth--codex-authorize-url
  "https://auth.openai.com/oauth/authorize"
  "OpenAI Codex OAuth authorization endpoint.")

(defconst gptel-oauth--codex-token-url
  "https://auth.openai.com/oauth/token"
  "OpenAI Codex OAuth token endpoint.")

(defconst gptel-oauth--codex-redirect-uri
  "http://localhost:1455/auth/callback"
  "OpenAI Codex OAuth redirect URI (local callback).")

(defconst gptel-oauth--codex-scope
  "openid profile email offline_access"
  "Requested scopes for OpenAI Codex OAuth.")

(defun gptel-oauth--codex-do-login ()
  "Run the OpenAI Codex OAuth PKCE flow.
Starts a local server on :1455, opens a browser window, and waits
for the callback.  Falls back to manual URL paste if needed.
Returns a credentials plist with :access :refresh :expires :account-id."
  (let* ((pkce      (gptel-oauth--generate-pkce))
         (verifier  (car pkce))
         (challenge (cdr pkce))
         (state     (gptel-oauth--base64url-encode
                     (apply #'unibyte-string
                            (cl-loop repeat 16 collect (random 256)))))
         (params    (url-build-query-string
                     `(("response_type"           "code")
                       ("client_id"               ,gptel-oauth--codex-client-id)
                       ("redirect_uri"            ,gptel-oauth--codex-redirect-uri)
                       ("scope"                   ,gptel-oauth--codex-scope)
                       ("code_challenge"          ,challenge)
                       ("code_challenge_method"   "S256")
                       ("state"                   ,state)
                       ("id_token_add_organizations" "true")
                       ("codex_cli_simplified_flow"  "true")
                       ("originator"                 "gptel"))))
         (auth-url  (concat gptel-oauth--codex-authorize-url "?" params))
         (server-ok (gptel-oauth--start-callback-server state))
         code)

    (message "gptel-oauth: Opening browser for OpenAI Codex authentication...")
    (browse-url auth-url)

    (if server-ok
        ;; Try automatic capture first (120 s timeout)
        (progn
          (message "gptel-oauth: Waiting for browser callback (up to 120 s)…")
          (setq code (gptel-oauth--wait-for-callback 120))
          (gptel-oauth--stop-callback-server))
      ;; No server -- go straight to manual entry
      )

    ;; Fall back to manual paste if auto-capture failed or server not available
    (unless code
      (let* ((raw (read-string
                   (concat "Paste the redirect URL from the browser\n"
                           "(e.g. http://localhost:1455/auth/callback?code=…&state=…): ")))
             (parsed-code
              (if (string-match "code=\\([^&#]+\\)" raw) (match-string 1 raw) nil))
             (parsed-state
              (if (string-match "state=\\([^&#]+\\)" raw) (match-string 1 raw) nil)))
        (unless (equal parsed-state state)
          (error "gptel-oauth: State mismatch in redirect URL"))
        (setq code parsed-code)))

    (unless code
      (error "gptel-oauth: No authorization code received"))

    ;; Exchange code for tokens
    (message "gptel-oauth: Exchanging authorization code for tokens...")
    (let* ((resp (gptel-oauth--http-post
                  gptel-oauth--codex-token-url
                  `(("grant_type"    . "authorization_code")
                    ("client_id"     . ,gptel-oauth--codex-client-id)
                    ("code"          . ,code)
                    ("code_verifier" . ,verifier)
                    ("redirect_uri"  . ,gptel-oauth--codex-redirect-uri))
                  nil))                         ; form-encoded
           (access     (plist-get resp :access_token))
           (refresh    (plist-get resp :refresh_token))
           (expires-in (plist-get resp :expires_in))
           (acct-id    (gptel-oauth--codex-account-id access)))
      (unless (and access refresh)
        (error "gptel-oauth: Codex token exchange failed: %S" resp))
      (list :access     access
            :refresh    refresh
            :expires    (+ (* (float-time) 1000)
                           (* expires-in 1000))
            :account-id acct-id))))

(defun gptel-oauth--codex-refresh (refresh-token)
  "Refresh the Codex OAuth token using REFRESH-TOKEN.
Returns an updated credentials plist."
  (let* ((resp (gptel-oauth--http-post
                gptel-oauth--codex-token-url
                `(("grant_type"    . "refresh_token")
                  ("refresh_token" . ,refresh-token)
                  ("client_id"     . ,gptel-oauth--codex-client-id))
                nil))
         (access     (plist-get resp :access_token))
         (refresh    (plist-get resp :refresh_token))
         (expires-in (plist-get resp :expires_in))
         (acct-id    (gptel-oauth--codex-account-id access)))
    (unless (and access refresh)
      (error "gptel-oauth: Codex token refresh failed: %S" resp))
    (list :access     access
          :refresh    refresh
          :expires    (+ (* (float-time) 1000)
                         (* expires-in 1000))
          :account-id acct-id)))

;; ============================================================================
;; Credential getter / auto-refresh helpers
;; ============================================================================

(defun gptel-oauth--ensure-credentials (provider-id refresh-fn)
  "Return valid credentials for PROVIDER-ID, refreshing if expired.
REFRESH-FN is called with the refresh token and should return a
new credentials plist.  Signals an error if no credentials are stored."
  (let ((creds (gptel-oauth--get-credentials provider-id)))
    (unless creds
      (user-error "gptel-oauth: No credentials for %s; call `gptel-oauth-login-%s' first"
                  provider-id provider-id))
    ;; Refresh if within 5 minutes of expiry (or already expired)
    (when (< (plist-get creds :expires)
             (+ (* (float-time) 1000) (* 5 60 1000)))
      (message "gptel-oauth: Refreshing %s token..." provider-id)
      (condition-case err
          (setq creds (funcall refresh-fn (plist-get creds :refresh)))
        (error
         (user-error "gptel-oauth: Token refresh for %s failed (%s); \
please re-run `gptel-oauth-login-%s'"
                     provider-id (error-message-string err) provider-id)))
      (gptel-oauth--set-credentials provider-id creds))
    creds))

(defun gptel-oauth--anthropic-key-fn ()
  "Return the Anthropic OAuth access token, refreshing if needed."
  (plist-get
   (gptel-oauth--ensure-credentials "anthropic" #'gptel-oauth--anthropic-refresh)
   :access))

(defun gptel-oauth--codex-key-fn ()
  "Return the Codex OAuth access token, refreshing if needed."
  (plist-get
   (gptel-oauth--ensure-credentials "codex" #'gptel-oauth--codex-refresh)
   :access))

(defun gptel-oauth--codex-account-id-fn ()
  "Return the Codex account ID from stored credentials."
  (or (plist-get (gptel-oauth--get-credentials "codex") :account-id)
      (error "gptel-oauth: No Codex credentials; call `gptel-oauth-login-codex' first")))

;; ============================================================================
;; Anthropic OAuth backend
;; ============================================================================

;; We subclass gptel-anthropic so all the Anthropic message parsing, streaming
;; etc. is reused unchanged.  We only override header generation and request
;; data building (to inject the mandatory "Claude Code" identity system prompt).

(cl-defstruct (gptel-anthropic-oauth
               (:constructor gptel--make-anthropic-oauth)
               (:copier nil)
               (:include gptel-anthropic)))

(defconst gptel-oauth--anthropic-claude-code-version "2.1.2"
  "Version string sent in the User-Agent / header for Claude Code identity.")

(defun gptel-oauth--anthropic-header ()
  "Build request headers for Anthropic OAuth (Bearer auth + CC identity)."
  (when-let* ((token (gptel--get-api-key)))
    `(("Authorization" . ,(concat "Bearer " token))
      ("anthropic-version" . "2023-06-01")
      ("anthropic-beta"
       . ,(concat "claude-code-20250219,oauth-2025-04-20,"
                  "fine-grained-tool-streaming-2025-05-14,"
                  "interleaved-thinking-2025-05-14,"
                  "extended-cache-ttl-2025-04-11"))
      ("user-agent"
       . ,(concat "claude-cli/" gptel-oauth--anthropic-claude-code-version
                  " (external, cli)"))
      ("x-app" . "cli"))))

(cl-defmethod gptel--request-data ((backend gptel-anthropic-oauth) prompts)
  "Build the Anthropic Messages API request, prepending the CC identity system."
  ;; Call the parent method first to get the standard plist
  (let* ((plist (cl-call-next-method backend prompts))
         (existing-system (plist-get plist :system))
         (identity "You are Claude Code, Anthropic's official CLI for Claude.")
         (identity-block `(:type "text" :text ,identity)))
    ;; Prepend "Claude Code" identity to the system prompt
    (plist-put plist :system
               (cond
                ;; No system prompt at all
                ((or (null existing-system) (eq existing-system :null))
                 (vector identity-block))
                ;; Already a vector of content blocks
                ((vectorp existing-system)
                 (vconcat (vector identity-block) existing-system))
                ;; Plain string
                ((stringp existing-system)
                 (vector identity-block
                         `(:type "text" :text ,existing-system)))
                ;; Anything else (shouldn't happen), wrap it
                (t (vector identity-block))))
    plist))

;;;###autoload
(cl-defun gptel-make-anthropic-oauth
    (name &key curl-args stream request-params
          (key  #'gptel-oauth--anthropic-key-fn)
          (header #'gptel-oauth--anthropic-header)
          (models gptel--anthropic-models)
          (host "api.anthropic.com")
          (protocol "https")
          (endpoint "/v1/messages"))
  "Register an Anthropic Claude OAuth backend for gptel with NAME.

This backend authenticates via Claude Pro/Max OAuth (PKCE), using the
same Messages API as the regular Anthropic backend but with Bearer token
auth and Claude Code identity headers required by the OAuth endpoint.

Run `gptel-oauth-login-anthropic' once to obtain credentials.

Keyword arguments are the same as `gptel-make-anthropic', with the
exception that KEY defaults to the OAuth token getter and HEADER
defaults to the OAuth-specific header function."
  (declare (indent 1))
  (let ((backend (gptel--make-anthropic-oauth
                  :curl-args curl-args
                  :name      name
                  :host      host
                  :header    header
                  :key       key
                  :models    (gptel--process-models models)
                  :protocol  protocol
                  :endpoint  endpoint
                  :stream    stream
                  :request-params request-params
                  :url (if protocol
                           (concat protocol "://" host endpoint)
                         (concat host endpoint)))))
    (prog1 backend
      (setf (alist-get name gptel--known-backends nil nil #'equal) backend))))

;; ============================================================================
;; OpenAI Codex backend  (Responses API)
;; ============================================================================

;; The Codex CLI uses the OpenAI Responses API at
;; https://chatgpt.com/backend-api/codex/responses
;; rather than the standard Chat Completions API.  The SSE stream uses
;; different event types (response.output_text.delta, response.completed, …).

(cl-defstruct (gptel-codex
               (:constructor gptel--make-codex)
               (:copier nil)
               (:include gptel-openai)))

;; ---- Stream parser -----------------------------------------------------------

(cl-defmethod gptel-curl--parse-stream ((_backend gptel-codex) info)
  "Parse a Codex Responses API SSE data stream.
Accumulates text from `response.output_text.delta' events and
returns the text collected since the last call.  Updates INFO with
stop-reason and token usage when `response.completed' arrives."
  (let ((parts nil)
        (pt    (point)))
    (condition-case nil
        (while (re-search-forward "^data:" nil t)
          (setq pt (match-beginning 0))
          (skip-chars-forward " ")
          (when (looking-at "\\[DONE\\]") (forward-line 1))
          (let* ((event   (gptel--json-read))
                 (type    (plist-get event :type)))
            (pcase type
              ("response.output_text.delta"
               (when-let* ((delta (plist-get event :delta)))
                 (push delta parts)))
              ((or "response.completed" "response.done")
               (let* ((resp  (plist-get event :response))
                      (usage (plist-get resp :usage)))
                 (plist-put info :stop-reason  "stop")
                 (plist-put info :output-tokens
                            (or (plist-get usage :output_tokens)
                                (plist-get usage :completion_tokens)))))
              ("response.failed"
               (let* ((resp (plist-get event :response))
                      (err  (plist-get resp :error))
                      (msg  (or (plist-get err :message) "Codex response failed")))
                 (error "gptel-oauth(codex): %s" msg)))
              ("error"
               (let ((msg (or (plist-get event :message)
                              (plist-get event :code)
                              "Unknown Codex error")))
                 (error "gptel-oauth(codex): %s" msg))))))
      (error (goto-char pt)))
    (apply #'concat (nreverse parts))))

;; ---- Non-streaming response parser ------------------------------------------

(cl-defmethod gptel--parse-response ((_backend gptel-codex) response info)
  "Parse a non-streaming Codex Responses API RESPONSE."
  (plist-put info :stop-reason "stop")
  (plist-put info :output-tokens
             (map-nested-elt response '(:usage :output_tokens)))
  ;; output is an array of items; we want the first message's text content
  (cl-loop
   for item across (plist-get response :output)
   when (equal (plist-get item :type) "message")
   return
   (cl-loop
    for block across (plist-get item :content)
    when (equal (plist-get block :type) "output_text")
    concat (plist-get block :text))))

;; ---- Request data builder ---------------------------------------------------

(defun gptel-oauth--codex-convert-messages (prompts)
  "Convert gptel PROMPTS list to Codex Responses API input format.
Returns a vector of message objects."
  (vconcat
   (mapcar
    (lambda (msg)
      (let ((role    (plist-get msg :role))
            (content (plist-get msg :content)))
        (list :role    role
              :content (cond
                        ((stringp content) content)
                        ((vectorp content)
                         ;; extract text from content blocks
                         (mapconcat (lambda (b) (or (plist-get b :text) ""))
                                    content ""))
                        (t (prin1-to-string content))))))
    prompts)))

(cl-defmethod gptel--request-data ((_backend gptel-codex) prompts)
  "Build the Codex Responses API request body from PROMPTS."
  (let ((plist
         `(:model  ,(gptel--model-name gptel-model)
           :store  :json-false
           :stream ,(or gptel-stream :json-false)
           :text   (:verbosity "medium")
           :input  ,(gptel-oauth--codex-convert-messages prompts))))
    (when gptel--system-message
      (plist-put plist :instructions gptel--system-message))
    (when gptel-max-tokens
      (plist-put plist :max_output_tokens gptel-max-tokens))
    ;; Merge backend and model request-params last
    (gptel--merge-plists
     plist
     gptel--request-params
     (gptel-backend-request-params gptel-backend)
     (gptel--model-request-params  gptel-model))))

;; ---- Buffer parser (reuse OpenAI's; Codex input accepts the same format) ----
;; gptel-codex inherits gptel-openai so gptel--parse-buffer dispatches to the
;; OpenAI implementation, which produces standard role/content plists.  That is
;; fine for Codex because gptel-oauth--codex-convert-messages handles them.

;; ---- Headers ----------------------------------------------------------------

(defun gptel-oauth--codex-header ()
  "Build request headers for Codex OAuth (Bearer + account-id)."
  (when-let* ((token    (gptel--get-api-key))
              (acct-id  (gptel-oauth--codex-account-id-fn)))
    `(("Authorization"      . ,(concat "Bearer " token))
      ("chatgpt-account-id" . ,acct-id)
      ("OpenAI-Beta"        . "responses=experimental")
      ("originator"         . "gptel"))))

;; ---- Codex models -----------------------------------------------------------

(defconst gptel--codex-models
  '((codex-mini-latest
     :description "Latest Codex Mini model (fast, efficient)"
     :capabilities (tool-use)
     :context-window 200
     :cutoff-date "2024-12")
    (gpt-4o
     :description "GPT-4o via Codex subscription"
     :capabilities (media tool-use)
     :mime-types ("image/jpeg" "image/png" "image/gif" "image/webp")
     :context-window 128
     :cutoff-date "2024-04")
    (gpt-4o-mini
     :description "GPT-4o Mini via Codex subscription"
     :capabilities (tool-use)
     :context-window 128
     :cutoff-date "2024-07")
    (o3
     :description "OpenAI o3 reasoning model"
     :capabilities (tool-use)
     :context-window 200
     :cutoff-date "2024-12")
    (o4-mini
     :description "OpenAI o4-mini reasoning model"
     :capabilities (tool-use)
     :context-window 200
     :cutoff-date "2024-12"))
  "Available models for the Codex backend.")

;;;###autoload
(cl-defun gptel-make-codex
    (name &key curl-args stream request-params
          (key    #'gptel-oauth--codex-key-fn)
          (header #'gptel-oauth--codex-header)
          (models gptel--codex-models)
          (host     "chatgpt.com")
          (protocol "https")
          (endpoint "/backend-api/codex/responses"))
  "Register an OpenAI Codex OAuth backend for gptel with NAME.

This backend authenticates with a ChatGPT Plus/Pro OAuth token and
routes requests through the Codex Responses API endpoint at
chatgpt.com/backend-api/codex/responses.

Run `gptel-oauth-login-codex' once to obtain credentials.

Keyword arguments:

CURL-ARGS (optional) extra Curl arguments.
STREAM    boolean, enable streaming (default nil).
MODELS    list of model specs (defaults to `gptel--codex-models').
HOST      API host (default \"chatgpt.com\").
PROTOCOL  protocol (default \"https\").
ENDPOINT  API path (default \"/backend-api/codex/responses\")."
  (declare (indent 1))
  (let ((backend (gptel--make-codex
                  :curl-args curl-args
                  :name      name
                  :host      host
                  :header    header
                  :key       key
                  :models    (gptel--process-models models)
                  :protocol  protocol
                  :endpoint  endpoint
                  :stream    stream
                  :request-params request-params
                  :url (if protocol
                           (concat protocol "://" host endpoint)
                         (concat host endpoint)))))
    (prog1 backend
      (setf (alist-get name gptel--known-backends nil nil #'equal) backend))))

;; ============================================================================
;; Interactive login / logout commands
;; ============================================================================

;;;###autoload
(defun gptel-oauth-login-anthropic ()
  "Authenticate gptel with Anthropic via Claude Pro/Max OAuth.

Opens a browser to claude.ai for authorization, then prompts you
to paste the authorization code (or full redirect URL) back into
Emacs.  Credentials are saved to `gptel-oauth-credentials-file'
and auto-refreshed before each request.

After logging in, create a backend with `gptel-make-anthropic-oauth'."
  (interactive)
  (let ((creds (gptel-oauth--anthropic-do-login)))
    (gptel-oauth--set-credentials "anthropic" creds)
    (message "gptel-oauth: Anthropic authentication successful!")))

;;;###autoload
(defun gptel-oauth-login-codex ()
  "Authenticate gptel with OpenAI Codex via ChatGPT Plus/Pro OAuth.

Opens a browser to auth.openai.com for authorization.  A local
HTTP server is started on port 1455 to capture the callback
automatically; if that is not possible, you will be asked to
paste the redirect URL.  Credentials are saved to
`gptel-oauth-credentials-file' and auto-refreshed before each request.

After logging in, create a backend with `gptel-make-codex'."
  (interactive)
  (let ((creds (gptel-oauth--codex-do-login)))
    (gptel-oauth--set-credentials "codex" creds)
    (message "gptel-oauth: Codex authentication successful! Account ID: %s"
             (plist-get creds :account-id))))

;;;###autoload
(defun gptel-oauth-logout (&optional provider)
  "Remove saved OAuth credentials for PROVIDER (\"anthropic\" or \"codex\").
When called interactively, prompts for the provider to log out from.
Pass \"all\" to remove all stored OAuth credentials."
  (interactive
   (list (completing-read "Log out from provider: "
                          '("anthropic" "codex" "all")
                          nil t)))
  (cond
   ((equal provider "all")
    (setq gptel-oauth--credentials nil)
    (gptel-oauth--save-credentials)
    (message "gptel-oauth: Logged out from all providers."))
   (provider
    (gptel-oauth--delete-credentials provider)
    (message "gptel-oauth: Logged out from %s." provider))
   (t (user-error "gptel-oauth: No provider specified"))))

(provide 'gptel-oauth)
;;; gptel-oauth.el ends here

;; Local Variables:
;; byte-compile-warnings: (not docstrings)
;; End:
