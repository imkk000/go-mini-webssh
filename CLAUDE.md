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

## What has been built in this conversation

- Initial project (single-session WebSocket SSH proxy + xterm.js UI)
- **Multi-tab support**: multiple simultaneous SSH sessions as browser tabs
- **Auto-disconnect**: `beforeunload` closes all WebSockets; `exit` in terminal auto-closes tab after 1.5s
- **End-to-end encryption**: ECDH + AES-256-GCM on every session (see Security layer above)
- **Session name**: optional custom label in the connect form; falls back to `user@host:port`
- **Clear form button**: "Clear" button next to "Connect" resets all fields (host, port→22, username, password, key, passphrase, session name) and switches auth tab back to Password
