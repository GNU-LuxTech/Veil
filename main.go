// Veil is the official P2P messaging application.
// Official source: https://github.com/GNU-LuxTech/Veil

/*
Copyright (c) 2026 Veil. All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
*/

package main

import (
	"bufio"
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cretz/bine/tor"
	"github.com/cretz/bine/torutil"
	torutil_ed25519 "github.com/cretz/bine/torutil/ed25519"
	"golang.org/x/crypto/chacha20poly1305"
)

//go:embed tor.exe
var torBinary []byte

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

	// Step 1: Generate Identity
	fmt.Println("  [VEIL] generating identity keypair...")
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal("failed to generate keypair", err)
	}

	// Step 1.5: Extract Embedded Tor
	extractedExe := extractTor(*listenFlag)

	// Step 2: Start Tor Daemon
	fmt.Println("  [VEIL] starting tor daemon (may take 30-60s)...")
	torConf := &tor.StartConf{
		DataDir: torDataDir(*listenFlag),
		ExePath: extractedExe, // Point to our newly extracted binary!
		ExtraArgs: []string{
			"--quiet",
			"--Log", "notice file " + filepath.Join(torDataDir(*listenFlag), "tor.log"),
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
		runDialer(t, *connectFlag, privateKey)
	}
}

// extractTor writes the embedded tor.exe to the data directory so we can run it
func extractTor(isListener bool) string {
	dataDir := torDataDir(isListener)
	
	// Ensure the directory exists
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		fatal("failed to create tor data directory", err)
	}

	exePath := filepath.Join(dataDir, "tor.exe")
	
	// Check if we already extracted it (to save time on reboot)
	if _, err := os.Stat(exePath); os.IsNotExist(err) {
		fmt.Println("  [VEIL] extracting embedded tor binary...")
		if err := os.WriteFile(exePath, torBinary, 0700); err != nil {
			fatal("failed to extract tor binary", err)
		}
	}
	
	return exePath
}

// runListener handles incoming connections
func runListener(t *tor.Tor, privateKey ed25519.PrivateKey) {
	// Create the Onion Service in Tor
	fmt.Println("  [VEIL] creating onion service...")
	listenCtx, listenCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer listenCancel()

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
		
		fmt.Println("  [VEIL] incoming connection received! authenticating...")
		
		peerAddress, aead, err := performHandshake(conn, true, privateKey)
		if err != nil {
			fmt.Println("  [ERROR] connection rejected (handshake failed):", err)
			conn.Close()
			continue
		}

		fmt.Printf("\n  [!] INCOMING CONNECTION FROM: %s.onion\n", peerAddress)
		fmt.Print("  Accept? (y/n): ")
		
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		
		if response != "y" && response != "yes" {
			fmt.Println("  [VEIL] connection rejected.")
			conn.Write([]byte{0x00}) // Tell the dialer we rejected
			conn.Close()
			continue
		}
		
		conn.Write([]byte{0x01}) // Tell the dialer we accepted
		handleSession(conn, aead)
		
		fmt.Println("  [VEIL] session closed.")
		conn.Close()
	}
}

// runDialer connects to another Veil node
func runDialer(t *tor.Tor, targetAddress string, privateKey ed25519.PrivateKey) {
	targetAddress = strings.TrimSuffix(targetAddress, ".onion")
	fmt.Printf("  [VEIL] connecting to %s.onion ...\n", targetAddress)
	
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer dialCancel()

	// tor.Dialer gives us a way to connect out through the Tor network
	dialer, err := t.Dialer(dialCtx, nil)
	if err != nil {
		fatal("failed to get tor dialer", err)
	}

	// Dial the remote onion address
	conn, err := dialer.DialContext(dialCtx, "tcp", targetAddress+".onion:7777")
	if err != nil {
		fatal("connection failed", err)
	}
	defer conn.Close()

	peerAddress, aead, err := performHandshake(conn, false, privateKey)
	if err != nil {
		fatal("handshake failed", err)
	}
	
	// MITM Protection: Ensure the server's identity matches the address we dialed
	if peerAddress != targetAddress {
		fatal("MITM DETECTED!", fmt.Errorf("expected server %s.onion, but server proved identity %s.onion", targetAddress, peerAddress))
	}

	fmt.Println("  [VEIL] identity verified! waiting for peer to accept...")
	
	// Wait for the explicit acceptance signal from the listener
	status := make([]byte, 1)
	if _, err := io.ReadFull(conn, status); err != nil {
		fatal("connection dropped while waiting for peer", err)
	}
	if status[0] == 0x00 {
		fatal("connection rejected by peer", nil)
	}

	fmt.Println("  [VEIL] peer accepted! connection established.")
	handleSession(conn, aead)
	fmt.Println("  [VEIL] session closed.")
}

// handleSession orchestrates the encrypted I/O
func handleSession(conn net.Conn, aead cipher.AEAD) {
	fmt.Println("────────────────────────────────────────────────────────────────")
	fmt.Println("  [VEIL] E2EE session established. type to chat.")
	fmt.Println("────────────────────────────────────────────────────────────────")

	// Start reader and writer loops
	go secureReader(conn, aead)
	secureWriter(conn, aead)
}

// performHandshake exchanges X25519 public keys, verifies identities, and derives a 32-byte shared secret
func performHandshake(conn net.Conn, isServer bool, myIdentity ed25519.PrivateKey) (string, cipher.AEAD, error) {
	// 1. Generate an ephemeral (temporary) X25519 keypair for this session
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate ecdh key: %w", err)
	}
	pub := priv.PublicKey().Bytes() // 32 bytes

	myEdPub := myIdentity.Public().(ed25519.PublicKey) // 32 bytes
	
	// 2. Sign the X25519 Ephemeral Public Key with our Ed25519 Identity Key
	signature := ed25519.Sign(myIdentity, pub) // 64 bytes
	
	// Payload: [32-byte X25519 Pub] [32-byte Ed25519 Pub] [64-byte Signature] = 128 bytes
	payload := append(pub, myEdPub...)
	payload = append(payload, signature...)

	peerPayload := make([]byte, 128)
	
	// Exchange payloads based on role
	if isServer {
		if _, err := io.ReadFull(conn, peerPayload); err != nil {
			return "", nil, fmt.Errorf("failed to read peer payload: %w", err)
		}
		if _, err := conn.Write(payload); err != nil {
			return "", nil, fmt.Errorf("failed to send payload: %w", err)
		}
	} else {
		if _, err := conn.Write(payload); err != nil {
			return "", nil, fmt.Errorf("failed to send payload: %w", err)
		}
		if _, err := io.ReadFull(conn, peerPayload); err != nil {
			return "", nil, fmt.Errorf("failed to read peer payload: %w", err)
		}
	}

	peerX25519Pub := peerPayload[0:32]
	peerEdPub := peerPayload[32:64]
	peerSig := peerPayload[64:128]

	// 3. Verify Peer's Identity Signature
	if !ed25519.Verify(ed25519.PublicKey(peerEdPub), peerX25519Pub, peerSig) {
		return "", nil, fmt.Errorf("invalid identity signature from peer")
	}

	// 4. Compute the Shared Secret
	peerKey, err := ecdh.X25519().NewPublicKey(peerX25519Pub)
	if err != nil {
		return "", nil, fmt.Errorf("invalid peer public key: %w", err)
	}

	secret, err := priv.ECDH(peerKey)
	if err != nil {
		return "", nil, fmt.Errorf("ecdh failed: %w", err)
	}

	// Hash the raw secret to ensure a uniform 32-byte key for ChaCha20
	hash := sha256.Sum256(secret)
	aead, err := chacha20poly1305.NewX(hash[:])
	if err != nil {
		return "", nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// 5. Convert the peer's Ed25519 Public Key to a .onion address
	peerAddress := torutil.OnionServiceIDFromV3PublicKey(torutil_ed25519.PublicKey(peerEdPub))

	return peerAddress, aead, nil
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
