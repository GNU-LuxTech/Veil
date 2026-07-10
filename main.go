package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
)

func main() {
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
	fmt.Println("────────────────────────────────────────")

	// Generate an Ed25519 keypair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("[ERROR] failed to generate keypair:", err)
		return
	}

	// Derive a Tor v3-style address from the public key
	// Real Tor v3 onion addresses are base32(pubkey + checksum + version)
	// This is a simplified preview — full Tor integration comes in Phase 1 Step 3
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(publicKey)
	onionAddr := strings.ToLower(encoded) + ".onion" // 52 chars — full 56 come with Tor checksum in Step 3

	fmt.Println()
	fmt.Println("  [VEIL] keypair generated.")
	fmt.Println()
	fmt.Printf("  your address  :  %s\n", onionAddr)
	fmt.Printf("  public key    :  %x\n", publicKey)
	fmt.Println()
	fmt.Println("  [VEIL] private key exists in memory only.")
	fmt.Println("  [VEIL] this address is not yet backed by a live Tor circuit.")
	fmt.Println("  [VEIL] tor integration: Phase 1 Step 3.")
	fmt.Println()
	fmt.Println("────────────────────────────────────────")

	// Suppress unused variable warning — privateKey will be used in Step 3
	_ = privateKey
}
