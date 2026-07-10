package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cretz/bine/tor"
)

func main() {
	printBanner()

	// --- Step 1: Generate Ed25519 keypair ---
	fmt.Println("  [VEIL] generating identity keypair...")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal("failed to generate keypair", err)
	}

	// Preview address (pre-Tor) — 52-char base32 of pubkey
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(publicKey)
	previewAddr := strings.ToLower(encoded) + ".onion"
	fmt.Printf("  [VEIL] keypair ready. preview address: %s\n", previewAddr)
	fmt.Println()

	// --- Step 2: Start embedded Tor daemon ---
	fmt.Println("  [VEIL] starting tor daemon...")
	fmt.Println("  [VEIL] this may take 30–60 seconds on first run...")
	fmt.Println()

	// tor.Start() looks for 'tor' in PATH. It will:
	// 1. Spin up a tor process
	// 2. Wait until it bootstraps (connects to the Tor network)
	// 3. Return a handle we use to create onion services and make connections
	torConf := &tor.StartConf{
		// DataDir is where Tor stores its state, cached descriptors, etc.
		// We use a hidden folder in the user's home directory.
		DataDir: torDataDir(),
		// TorrcFile and ExePath: point directly at the tor.exe from Tor Browser.
		// Once we ship Veil, this will be replaced by an embedded binary.
		ExePath: `C:\Users\matti\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	t, err := tor.Start(ctx, torConf)
	if err != nil {
		fatal("failed to start tor — is tor installed and in PATH?", err)
	}
	defer t.Close()

	fmt.Println("  [VEIL] tor daemon started.")

	// --- Step 3: Create a v3 onion service using our Ed25519 key ---
	// This is where our keypair becomes a REAL .onion address on the Tor network.
	// The onion address IS derived from the public key — Tor verifies this cryptographically.
	fmt.Println("  [VEIL] creating onion service...")

	listenCtx, listenCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer listenCancel()

	// OnionService creates a hidden service. We pass our Ed25519 private key so
	// our .onion address is deterministic (same key = same address, every time).
	onion, err := t.Listen(listenCtx, &tor.ListenConf{
		LocalPort:  7777,               // local port the service forwards to
		RemotePorts: []int{7777},       // port exposed on the .onion address
		Key:        privateKey,         // our Ed25519 key — this DEFINES our address
		Version3:   true,               // use Tor v3 (Ed25519-based, 56-char addresses)
	})
	if err != nil {
		fatal("failed to create onion service", err)
	}
	defer onion.Close()

	// The real address — backed by a live Tor circuit, cryptographically tied to our key
	realAddr := onion.ID + ".onion"

	fmt.Println()
	fmt.Println("────────────────────────────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  [VEIL] onion service active.")
	fmt.Println()
	fmt.Printf("  your address  :  %s\n", realAddr)
	fmt.Printf("  public key    :  %x\n", publicKey)
	fmt.Println()
	fmt.Println("  share your address with trusted contacts only.")
	fmt.Println("  veil is now listening for incoming connections.")
	fmt.Println()
	fmt.Println("────────────────────────────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  press Ctrl+C to shut down.")
	fmt.Println()

	// Hold the process open — the onion service lives as long as we're running
	select {}
}

// torDataDir returns the path where Tor stores its state data.
// Using a hidden dot-folder in the user's home directory.
func torDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".veil-tor-data" // fallback to current directory
	}
	return home + "/.veil/tor"
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
