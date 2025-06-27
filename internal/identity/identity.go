package identity

import (
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

const privateKeyType = "PRIVATE KEY"

var (
	ErrMissingPEM       = errors.New("no PEM data found")
	ErrMissingFile      = errors.New("file not found")
	ErrInvalidKey       = errors.New("invalid key type")
	ErrInvalidSignature = errors.New("invalid signature")
)

func saveKey(key []byte, kType, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer file.Close()

	block := pem.Block{
		Bytes: key,
		Type:  kType,
	}
	if err := pem.Encode(file, &block); err != nil {
		return fmt.Errorf("encode key: %w", err)
	}

	return nil
}
