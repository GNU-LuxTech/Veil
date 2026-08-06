package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	saltSize  = 16
	nonceSize = 24
)

// deriveKey derives a 32-byte key from the passphrase using Argon2id.
func deriveKey(passphrase string, salt []byte) []byte {
	// Argon2id parameters: Time=3, Memory=64MB, Threads=4, KeyLen=32
	return argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32)
}

// encryptIdentity encrypts the 64-byte private key using the passphrase.
// Output format: [16-byte salt] | [24-byte nonce] | [encrypted payload + 16-byte tag]
func encryptIdentity(privKey ed25519.PrivateKey, passphrase string) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	key := deriveKey(passphrase, salt)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, privKey, nil)

	payload := make([]byte, len(salt)+len(nonce)+len(ciphertext))
	copy(payload[0:saltSize], salt)
	copy(payload[saltSize:saltSize+nonceSize], nonce)
	copy(payload[saltSize+nonceSize:], ciphertext)

	return payload, nil
}

// decryptIdentity decrypts the encrypted payload using the passphrase.
func decryptIdentity(payload []byte, passphrase string) (ed25519.PrivateKey, error) {
	minSize := saltSize + nonceSize + ed25519.PrivateKeySize + chacha20poly1305.Overhead
	if len(payload) < minSize {
		return nil, errors.New("invalid or corrupted identity file size")
	}

	salt := payload[0:saltSize]
	nonce := payload[saltSize : saltSize+nonceSize]
	ciphertext := payload[saltSize+nonceSize:]

	key := deriveKey(passphrase, salt)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	privKeyBytes, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("incorrect passphrase or corrupted identity key")
	}

	if len(privKeyBytes) != ed25519.PrivateKeySize {
		return nil, errors.New("decrypted key size is invalid")
	}

	return ed25519.PrivateKey(privKeyBytes), nil
}
