# CLAUDE.md — go-webssh project context

This file is for future Claude Code sessions. Read it before making changes.

## What this project is

A single-binary, web-based SSH terminal client written in Go. The browser connects over WebSocket; the Go server proxies to SSH. No Node.js, no frontend build step — everything is a static file or compiled into the binary.

## Architecture

```
Browser (xterm.js)
  │  WebSocket (WS/WSS)
  │  └─ ECDH key exchange → AES-256-GCM encrypted frames
  ▼
Go server  (main.go)
  │  golang.org/x/crypto/ssh
  ▼
SSH server (PTY session)
```

**One WebSocket connection = one SSH session.** The backend is stateless — no session store, no pooling.

## Key files

| File | Purpose |
|------|---------|
| `main.go` | WebSocket upgrade, ECDH key exchange, AES-GCM encrypt/decrypt, SSH dial + PTY proxy |
| `static/index.html` | All frontend: multi-tab UI, Web Crypto key exchange, xterm.js terminals |
| `static/vendor/` | Self-hosted xterm.js v6.0.0, FitAddon v0.11.0, Monaspace Nerd Font |

## Security layer (important — do not remove)

Every session does a fresh **ECDH P-256 key exchange** at WebSocket open:

1. Server sends `{"type":"key","pub":"<base64 P-256 uncompressed>"}` as a plain text frame
2. Client generates its own ECDH key pair, sends its public key the same way
3. Both sides run **HKDF-SHA256** over the shared secret with salt `"webssh-session"` and info `"aes-256-gcm-key"` → 32-byte AES-256-GCM key
4. Every frame after that (SSH credentials, terminal I/O, resize events, error strings) is encrypted: `[12-byte random nonce][AES-GCM ciphertext+tag]`

The Go side: `deriveAESKey`, `encryptMsg`, `decryptMsg` in `main.go`. The `safeWriter.gcm` field is nil until key exchange completes; after that all `write`/`writeText` calls auto-encrypt.

The JS side: `doKeyExchange`, `encryptMsg`, `decryptMsg` in `index.html`. The session object's `aesKey` field is null until key exchange completes; `ws.onmessage` handles the text-frame key exchange first, then switches to decrypting binary frames.

**Salt and info strings must match exactly between Go and JS or sessions will silently fail.**

## Multi-tab session model (frontend)

Sessions are stored in a `Map<id, session>` where each session holds:
- `ws` — WebSocket
- `term` — xterm.js Terminal instance
- `fitAddon` — FitAddon (call `.fit()` whenever the slot becomes visible)
- `resizeObserver` — ResizeObserver on the terminal container div
- `tabEl` — the tab DOM element
- `slotEl` — the terminal slot div (positioned absolute, shown/hidden via `.active` class)
- `aesKey` — CryptoKey (null until key exchange done)
- `customName` — user-provided session label (may be empty string)

Tab label priority: `customName` → `user@host:port` (set in `setupTerminal`).

`closeSession(id)` is the single cleanup function — closes WS, disposes terminal, removes DOM, switches tab or returns to connect screen.

`ws.onclose` auto-calls `closeSession` after 1500 ms so the user sees the final terminal output before the tab disappears.

## Connect flow (per session)

1. User fills form, clicks Connect
2. Tab + terminal slot created immediately, workspace shown, overlay hidden
3. WebSocket opens → server sends key exchange text frame
4. `ws.onmessage` (text branch): `doKeyExchange` → `aesKey` set → send encrypted SSH config → `setupTerminal`
5. `ws.onmessage` (binary branch): decrypt → write to xterm
6. On close: write `[connection closed]`, setTimeout 1500ms → `closeSession`

## Backend flow (per WebSocket)

`handleWS` in `main.go`:
1. Upgrade HTTP → WebSocket
2. Generate ECDH key pair, send public key as text frame
3. Read client public key, derive AES-GCM key, set `sw.gcm`
4. Read + decrypt SSH config (ConnectConfig JSON)
5. Build auth methods (private key preferred, password fallback)
6. `ssh.Dial` → `NewSession` → `RequestPty` → `Shell`
7. Two goroutines copy SSH stdout/stderr → encrypted WS frames
8. Main goroutine reads encrypted WS frames → decrypt → resize or stdin write
9. On loop exit: close stdin, drain `done` channel, deferred cleanup

## Running

```sh
go run main.go              # HTTP :8080
go run main.go -addr :3000  # custom port
go run main.go -cert x.crt -key x.key  # TLS
```

## WebSocket keepalive (important for nginx deployments)

`main.go` runs a goroutine per session that sends a **WebSocket ping frame every 30 seconds** and a matching pong handler. This prevents nginx (and other reverse proxies) from closing idle connections.

**Common mistake**: setting nginx `keepalive_timeout` to a long value has no effect on WebSocket proxy sessions. The relevant nginx directives are `proxy_read_timeout` and `proxy_send_timeout` in the `/ws` location block. Without them, nginx drops idle WebSocket connections after the default 60 s.

Implementation detail: `pingStop` is a channel closed after `<-done` (when the SSH copy goroutines finish) to cleanly stop the ping goroutine.

## iPad / mobile terminal resize

On iOS/iPadOS, switching apps pauses layout — when the user returns, the viewport may have changed but `ResizeObserver` does not reliably fire. Three events trigger `refitActive()` with a 100 ms `setTimeout` (giving the browser time to finish compositing):

- `visibilitychange` → `visible` — main trigger when switching apps
- `window focus` — covers desktop/split-view focus changes
- `pageshow` — covers iOS back-forward cache restores (Safari BFCache)

The delay is intentional: calling `fitAddon.fit()` at event time gives stale dimensions on iOS.

## Light/Dark theme

The UI supports dark (default) and light themes via CSS custom properties on `:root` / `:root[data-theme="light"]`. Theme preference is saved in `localStorage` under the key `"webssh-theme"`.

- Toggle button: `☀`/`🌙` in the tab bar (when sessions exist) and a floating fixed button on the connect screen
- `TERMINAL_THEMES` in `index.html` holds separate xterm.js color palettes for each theme; `applyTheme()` updates all open terminals live via `term.options.theme`
- The floating toggle (`#theme-toggle-float`) is hidden when the tab bar is visible to avoid duplication

## What has been built

- Initial project (single-session WebSocket SSH proxy + xterm.js UI)
- **Multi-tab support**: multiple simultaneous SSH sessions as browser tabs
- **Auto-disconnect**: `beforeunload` closes all WebSockets; `exit` in terminal auto-closes tab after 1.5s
- **End-to-end encryption**: ECDH + AES-256-GCM on every session (see Security layer above)
- **Session name**: optional custom label in the connect form; falls back to `user@host:port`
- **Clear form button**: "Clear" button next to "Connect" resets all fields (host, port→22, username, password, key, passphrase, session name) and switches auth tab back to Password
- **WebSocket ping keepalive**: server pings every 30 s; fixes dropped connections through nginx (proxy_read_timeout, not keepalive_timeout)
- **Light/Dark theme toggle**: CSS variable-based theming, persisted in localStorage, terminals update live
- **iPad/mobile resize fix**: `visibilitychange`, `focus`, and `pageshow` events each call `refitActive()` with a 100 ms delay so the terminal re-fits when the user switches apps and returns
