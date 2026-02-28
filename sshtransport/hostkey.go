package sshtransport

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// GenerateHostKey generates a new Ed25519 host key.
func GenerateHostKey() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ed25519 key: %w", err)
	}
	return ssh.NewSignerFromKey(priv)
}

// LoadHostKey loads a host key from a PEM-encoded private key file.
func LoadHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading host key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parsing host key: %w", err)
	}
	return signer, nil
}

// LoadOrGenerateHostKey loads a host key from path if it exists, or generates
// a new Ed25519 key, writes it to path, and returns the signer.
func LoadOrGenerateHostKey(path string) (ssh.Signer, error) {
	if _, err := os.Stat(path); err == nil {
		return LoadHostKey(path)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ed25519 key: %w", err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}

	pemData := pem.EncodeToMemory(pemBlock)
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		return nil, fmt.Errorf("writing host key: %w", err)
	}

	return ssh.NewSignerFromKey(priv)
}
