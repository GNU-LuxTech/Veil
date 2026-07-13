package main

import (
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/cretz/bine/tor"
	"golang.org/x/crypto/chacha20poly1305"
)

func main() {
	// Parse command line flags
	listenFlag := flag.Bool("listen", false, "Listen for incoming connections")
	connectFlag := flag.String("connect", "", "Connect to a peer's onion address")
	flag.Parse()

	printBanner()

	if !*listenFlag && *connectFlag == "" {
		fmt.Println("  [VEIL] Please specify --listen or --connect <address>")
		os.Exit(1)
	}

	// Step 1: Generate Identity (We need this for both connecting and listening eventually)
	fmt.Println("  [VEIL] generating identity keypair...")
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal("failed to generate keypair", err)
	}

	// Step 2: Start Tor Daemon
	fmt.Println("  [VEIL] starting tor daemon (may take 30-60s)...")
	torConf := &tor.StartConf{
		DataDir: torDataDir(*listenFlag),
		ExePath: `C:\Users\matti\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`, // TODO: Fix hardcoded path for portability
		ExtraArgs: []string{
			"--quiet",
			"--Log", "notice file " + torDataDir(*listenFlag) + "/tor.log",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	t, err := tor.Start(ctx, torConf)
	if err != nil {
		fatal("failed to start tor", err)
	}
	defer t.Close()
	fmt.Println("  [VEIL] tor daemon started.")

	// Branch based on mode
	if *listenFlag {
		runListener(t, privateKey)
	} else if *connectFlag != "" {
		runDialer(t, *connectFlag)
	}
}

// runListener handles incoming connections
func runListener(t *tor.Tor, privateKey ed25519.PrivateKey) {
	// Create the Onion Service in Tor
	fmt.Println("  [VEIL] creating onion service...")
	listenCtx, listenCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer listenCancel()

	// bine's t.Listen creates both the Tor hidden service AND the local TCP listener automatically!
	onion, err := t.Listen(listenCtx, &tor.ListenConf{
		RemotePorts: []int{7777}, // Port exposed on the .onion address
		Key:         privateKey,
		Version3:    true,
	})
	if err != nil {
		fatal("failed to create onion service", err)
	}
	defer onion.Close()

	fmt.Printf("\n  [VEIL] listening at: %s.onion\n\n", onion.ID)

	// onion implements net.Listener, so we can Accept() directly on it!
	for {
		conn, err := onion.Accept()
		if err != nil {
			fmt.Println("  [ERROR] failed to accept connection:", err)
			continue
		}

		fmt.Println("  [VEIL] incoming connection received!")

		handleSession(conn, true)

		fmt.Println("  [VEIL] session closed.")
		conn.Close()
	}
}

// runDialer connects to another Veil node
func runDialer(t *tor.Tor, targetAddress string) {
	fmt.Printf("  [VEIL] connecting to %s ...\n", targetAddress)

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer dialCancel()

	// tor.Dialer gives us a way to connect out through the Tor network
	dialer, err := t.Dialer(dialCtx, nil)
	if err != nil {
		fatal("failed to get tor dialer", err)
	}

	// Dial the remote onion address
	conn, err := dialer.DialContext(dialCtx, "tcp", targetAddress+":7777")
	if err != nil {
		fatal("connection failed", err)
	}
	defer conn.Close()

	fmt.Println("  [VEIL] connected successfully!")

	handleSession(conn, false)
	fmt.Println("  [VEIL] session closed.")
}

// handleSession orchestrates the cryptographic handshake and starts encrypted I/O
func handleSession(conn net.Conn, isServer bool) {
	fmt.Println("  [VEIL] establishing secure session...")

	// 1. Handshake (X25519 Key Exchange)
	sharedSecret, err := performHandshake(conn, isServer)
	if err != nil {
		fmt.Println("  [ERROR] handshake failed:", err)
		return
	}

	// 2. Initialize ChaCha20-Poly1305 Cipher
	aead, err := chacha20poly1305.NewX(sharedSecret)
	if err != nil {
		fmt.Println("  [ERROR] failed to create cipher:", err)
		return
	}

	fmt.Println("────────────────────────────────────────────────────────────────")
	fmt.Println("  [VEIL] E2EE session established. type to chat.")
	fmt.Println("────────────────────────────────────────────────────────────────")

	// 3. Start reader and writer loops
	go secureReader(conn, aead)
	secureWriter(conn, aead)
}

// performHandshake exchanges X25519 public keys and derives a 32-byte shared secret
func performHandshake(conn net.Conn, isServer bool) ([]byte, error) {
	// Generate an ephemeral (temporary) X25519 keypair for this session
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ecdh key: %w", err)
	}
	pub := priv.PublicKey().Bytes() // 32 bytes

	peerPub := make([]byte, 32)

	// Exchange keys based on role
	if isServer {
		if _, err := io.ReadFull(conn, peerPub); err != nil {
			return nil, fmt.Errorf("failed to read peer key: %w", err)
		}
		if _, err := conn.Write(pub); err != nil {
			return nil, fmt.Errorf("failed to send key: %w", err)
		}
	} else {
		if _, err := conn.Write(pub); err != nil {
			return nil, fmt.Errorf("failed to send key: %w", err)
		}
		if _, err := io.ReadFull(conn, peerPub); err != nil {
			return nil, fmt.Errorf("failed to read peer key: %w", err)
		}
	}

	// Compute the shared secret
	peerKey, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("invalid peer public key: %w", err)
	}

	secret, err := priv.ECDH(peerKey)
	if err != nil {
		return nil, fmt.Errorf("ecdh failed: %w", err)
	}

	// Hash the raw secret to ensure a uniform 32-byte key for ChaCha20
	hash := sha256.Sum256(secret)
	return hash[:], nil
}

// secureReader continuously reads framed ciphertext, decrypts it, and prints to stdout
func secureReader(conn net.Conn, aead cipher.AEAD) {
	// XChaCha20Poly1305 uses a 24-byte nonce.
	// Frame Format: [2-byte length] [24-byte nonce] [ciphertext]
	lenBuf := make([]byte, 2)
	for {
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			fmt.Println("\n  [VEIL] connection dropped.")
			os.Exit(0)
		}

		msgLen := binary.BigEndian.Uint16(lenBuf)
		if msgLen == 0 {
			continue
		}

		cipherText := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, cipherText); err != nil {
			fmt.Println("\n  [VEIL] failed to read message.")
			os.Exit(0)
		}

		if len(cipherText) < aead.NonceSize() {
			fmt.Println("\n  [VEIL] invalid message format.")
			continue
		}

		nonce := cipherText[:aead.NonceSize()]
		actualCiphertext := cipherText[aead.NonceSize():]

		// Decrypt the message
		plaintext, err := aead.Open(nil, nonce, actualCiphertext, nil)
		if err != nil {
			fmt.Println("\n  [VEIL] decryption failed (tampering detected?)")
			continue
		}

		fmt.Printf("  [PEER] %s", string(plaintext))
	}
}

// secureWriter reads from keyboard, encrypts it, frames it, and sends it over the wire
func secureWriter(conn net.Conn, aead cipher.AEAD) {
	buf := make([]byte, 4096)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			return
		}

		plaintext := buf[:n]

		// Generate a unique random nonce for this message
		nonce := make([]byte, aead.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			fmt.Println("\n  [ERROR] failed to generate nonce")
			continue
		}

		// Encrypt the message
		ciphertext := aead.Seal(nil, nonce, plaintext, nil)

		// Combine nonce and ciphertext into a single payload
		frame := append(nonce, ciphertext...)

		// Create a 2-byte length prefix
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(len(frame)))

		// Send it over the wire
		conn.Write(lenBuf)
		conn.Write(frame)
	}
}

// torDataDir returns the path where Tor stores its state data.
func torDataDir(isListener bool) string {
	suffix := "connect"
	if isListener {
		suffix = "listen"
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return ".veil-tor-data-" + suffix
	}
	return home + "/.veil/tor-" + suffix
}

// fatal prints a formatted error and exits.
func fatal(msg string, err error) {
	fmt.Printf("\n  [ERROR] %s\n", msg)
	fmt.Printf("          %v\n\n", err)
	os.Exit(1)
}

// printBanner prints the Veil ASCII art header.
func printBanner() {
	fmt.Println()
	fmt.Println("  ██╗   ██╗███████╗██╗██╗     ")
	fmt.Println("  ██║   ██║██╔════╝██║██║     ")
	fmt.Println("  ██║   ██║█████╗  ██║██║     ")
	fmt.Println("  ╚██╗ ██╔╝██╔══╝  ██║██║     ")
	fmt.Println("   ╚████╔╝ ███████╗██║███████╗")
	fmt.Println("    ╚═══╝  ╚══════╝╚═╝╚══════╝")
	fmt.Println()
	fmt.Println("  ephemeral. encrypted. untraced.")
	fmt.Println()
	fmt.Println("────────────────────────────────────────────────────────────────")
	fmt.Println()
}
