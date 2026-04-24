package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
)

// ConnectConfig holds SSH connection parameters sent from the frontend.
type ConnectConfig struct {
	Host       string `json:"host"`
	Port       string `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"` // PEM-encoded private key (optional)
	Passphrase string `json:"passphrase"`  // passphrase for the private key (optional)
}

// ResizeMsg is sent by the frontend when the terminal is resized.
type ResizeMsg struct {
	Type string `json:"type"`
	Cols uint32 `json:"cols"`
	Rows uint32 `json:"rows"`
}

// KeyMsg is used for the ECDH public-key exchange at session start.
type KeyMsg struct {
	Type string `json:"type"`
	Pub  string `json:"pub"` // base64-encoded uncompressed P-256 public key
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// Allow all origins; restrict in production via the CheckOrigin callback.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// safeWriter serialises concurrent WebSocket writes (gorilla/websocket is not
// goroutine-safe for concurrent writes).  When gcm is set every outgoing
// message is encrypted with AES-256-GCM before being sent as a binary frame.
type safeWriter struct {
	mu   sync.Mutex
	conn *websocket.Conn
	gcm  cipher.AEAD // nil until key exchange completes
}

func (sw *safeWriter) write(data []byte) error {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	if sw.gcm != nil {
		enc, err := encryptMsg(sw.gcm, data)
		if err != nil {
			return err
		}
		return sw.conn.WriteMessage(websocket.BinaryMessage, enc)
	}
	return sw.conn.WriteMessage(websocket.BinaryMessage, data)
}

// writeText sends a human-readable message to the terminal.  After the key
// exchange it is encrypted and sent as a binary frame so the content stays
// invisible in network inspectors.
func (sw *safeWriter) writeText(msg string) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	if sw.gcm != nil {
		enc, err := encryptMsg(sw.gcm, []byte(msg))
		if err != nil {
			return
		}
		_ = sw.conn.WriteMessage(websocket.BinaryMessage, enc)
		return
	}
	_ = sw.conn.WriteMessage(websocket.TextMessage, []byte(msg))
}

// ── Crypto helpers ──────────────────────────────────────────────────────────

// deriveAESKey runs HKDF-SHA256 over the ECDH shared secret and returns an
// AES-256-GCM AEAD.
func deriveAESKey(sharedSecret []byte) (cipher.AEAD, error) {
	r := hkdf.New(sha256.New, sharedSecret,
		[]byte("webssh-session"),
		[]byte("aes-256-gcm-key"),
	)
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// encryptMsg prepends a random 12-byte nonce and returns nonce||ciphertext.
func encryptMsg(gcm cipher.AEAD, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// decryptMsg splits off the leading nonce and authenticates + decrypts.
func decryptMsg(gcm cipher.AEAD, data []byte) ([]byte, error) {
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, data[:ns], data[ns:], nil)
}

// ── SSH auth ────────────────────────────────────────────────────────────────

// buildAuthMethods constructs the SSH auth method list from the config.
// Private key auth is preferred when a key is provided; password auth is
// included as a fallback (or sole method) when a password is set.
func buildAuthMethods(cfg ConnectConfig) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	if cfg.PrivateKey != "" {
		var signer ssh.Signer
		var err error

		if cfg.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(
				[]byte(cfg.PrivateKey), []byte(cfg.Passphrase),
			)
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(cfg.PrivateKey))
		}
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if cfg.Password != "" {
		methods = append(methods, ssh.Password(cfg.Password))
	}

	if len(methods) == 0 {
		return nil, fmt.Errorf("no authentication method provided (password or private key required)")
	}
	return methods, nil
}

// ── WebSocket handler ────────────────────────────────────────────────────────

// handleWS upgrades an HTTP connection to WebSocket, performs an ECDH key
// exchange to establish a shared AES-256-GCM session key, then proxies
// encrypted data between the browser and an SSH server.
func handleWS(w http.ResponseWriter, r *http.Request) {
	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("websocket upgrade: %v", err)
		return
	}
	defer wsConn.Close()

	sw := &safeWriter{conn: wsConn}

	// ── 0. ECDH key exchange ─────────────────────────────────────────────────

	curve := ecdh.P256()
	serverPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		log.Printf("ecdh keygen: %v", err)
		return
	}

	// Send server public key (plain text frame – this is the exchange itself)
	serverKeyMsg, _ := json.Marshal(KeyMsg{
		Type: "key",
		Pub:  base64.StdEncoding.EncodeToString(serverPriv.PublicKey().Bytes()),
	})
	if err := wsConn.WriteMessage(websocket.TextMessage, serverKeyMsg); err != nil {
		log.Printf("send server key: %v", err)
		return
	}

	// Receive client public key
	wsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, clientKeyRaw, err := wsConn.ReadMessage()
	wsConn.SetReadDeadline(time.Time{})
	if err != nil {
		log.Printf("recv client key: %v", err)
		return
	}

	var clientKeyMsg KeyMsg
	if err := json.Unmarshal(clientKeyRaw, &clientKeyMsg); err != nil || clientKeyMsg.Type != "key" {
		log.Printf("invalid client key message")
		return
	}

	clientPubBytes, err := base64.StdEncoding.DecodeString(clientKeyMsg.Pub)
	if err != nil {
		log.Printf("decode client pub: %v", err)
		return
	}

	clientPub, err := curve.NewPublicKey(clientPubBytes)
	if err != nil {
		log.Printf("parse client pub: %v", err)
		return
	}

	sharedSecret, err := serverPriv.ECDH(clientPub)
	if err != nil {
		log.Printf("ecdh shared secret: %v", err)
		return
	}

	gcm, err := deriveAESKey(sharedSecret)
	if err != nil {
		log.Printf("derive aes key: %v", err)
		return
	}

	// All subsequent messages are now encrypted
	sw.gcm = gcm

	// ── 1. Read SSH config (encrypted binary frame) ──────────────────────────
	wsConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, encCfg, err := wsConn.ReadMessage()
	wsConn.SetReadDeadline(time.Time{})
	if err != nil {
		log.Printf("read config: %v", err)
		return
	}

	msg, err := decryptMsg(gcm, encCfg)
	if err != nil {
		sw.writeText(fmt.Sprintf("decryption error: %v\r\n", err))
		return
	}

	var cfg ConnectConfig
	if err := json.Unmarshal(msg, &cfg); err != nil {
		sw.writeText(fmt.Sprintf("invalid config: %v\r\n", err))
		return
	}
	if cfg.Port == "" {
		cfg.Port = "22"
	}

	// ── 2. Build auth methods ────────────────────────────────────────────────
	authMethods, err := buildAuthMethods(cfg)
	if err != nil {
		sw.writeText(fmt.Sprintf("auth config error: %v\r\n", err))
		return
	}

	// ── 3. Dial SSH ──────────────────────────────────────────────────────────
	sshCfg := &ssh.ClientConfig{
		User:            cfg.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec – acceptable for a terminal proxy
		Timeout:         15 * time.Second,
	}

	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
	sshClient, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		sw.writeText(fmt.Sprintf("\r\nSSH dial %s failed: %v\r\n", addr, err))
		return
	}
	defer sshClient.Close()
	log.Printf("SSH connected: %s@%s", cfg.Username, addr)

	// ── 4. Open an SSH session ───────────────────────────────────────────────
	session, err := sshClient.NewSession()
	if err != nil {
		sw.writeText(fmt.Sprintf("SSH session: %v\r\n", err))
		return
	}
	defer session.Close()

	// ── 5. Request a PTY ────────────────────────────────────────────────────
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 38400,
		ssh.TTY_OP_OSPEED: 38400,
	}
	if err := session.RequestPty("xterm-256color", 24, 80, modes); err != nil {
		sw.writeText(fmt.Sprintf("PTY request: %v\r\n", err))
		return
	}

	sshIn, err := session.StdinPipe()
	if err != nil {
		sw.writeText(fmt.Sprintf("stdin pipe: %v\r\n", err))
		return
	}

	sshOut, err := session.StdoutPipe()
	if err != nil {
		sw.writeText(fmt.Sprintf("stdout pipe: %v\r\n", err))
		return
	}

	sshErr, err := session.StderrPipe()
	if err != nil {
		sw.writeText(fmt.Sprintf("stderr pipe: %v\r\n", err))
		return
	}

	if err := session.Shell(); err != nil {
		sw.writeText(fmt.Sprintf("shell: %v\r\n", err))
		return
	}

	// ── 6. Pipe SSH → WebSocket (encrypted) ─────────────────────────────────
	done := make(chan struct{})

	copyToWS := func(src interface{ Read([]byte) (int, error) }) {
		buf := make([]byte, 4096)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if werr := sw.write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		select {
		case done <- struct{}{}:
		default:
		}
	}

	go copyToWS(sshOut)
	go copyToWS(sshErr)

	// ── WebSocket ping keepalive ─────────────────────────────────────────────
	// Sends a ping every 30 s so nginx proxy_read_timeout doesn't kill idle sessions.
	pingStop := make(chan struct{})
	wsConn.SetPongHandler(func(string) error { return nil })
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sw.mu.Lock()
				err := wsConn.WriteMessage(websocket.PingMessage, nil)
				sw.mu.Unlock()
				if err != nil {
					return
				}
			case <-pingStop:
				return
			}
		}
	}()

	// ── 7. Pipe WebSocket → SSH (decrypt then forward) ───────────────────────
	for {
		_, encData, err := wsConn.ReadMessage()
		if err != nil {
			break
		}

		data, err := decryptMsg(gcm, encData)
		if err != nil {
			log.Printf("decrypt client message: %v", err)
			break
		}

		// Check for a resize control message before forwarding as raw input.
		var resize ResizeMsg
		if json.Unmarshal(data, &resize) == nil && resize.Type == "resize" {
			if resize.Cols > 0 && resize.Rows > 0 {
				_ = session.WindowChange(int(resize.Rows), int(resize.Cols))
			}
			continue
		}

		if _, err := sshIn.Write(data); err != nil {
			break
		}
	}

	sshIn.Close()
	<-done
	close(pingStop)
	log.Printf("session closed: %s@%s", cfg.Username, addr)
}

func main() {
	addr := flag.String("addr", ":8080", "listen address (host:port)")
	certFile := flag.String("cert", "", "TLS certificate file (enables HTTPS/WSS)")
	keyFile := flag.String("key", "", "TLS private key file")
	flag.Parse()

	http.Handle("/", http.FileServer(http.Dir("static")))
	http.HandleFunc("/ws", handleWS)

	if *certFile != "" && *keyFile != "" {
		log.Printf("WebSSH listening on https://%s (WSS enabled)", *addr)
		log.Fatal(http.ListenAndServeTLS(*addr, *certFile, *keyFile, nil))
	} else {
		log.Printf("WebSSH listening on http://%s (use -cert/-key for WSS)", *addr)
		log.Fatal(http.ListenAndServe(*addr, nil))
	}
}
