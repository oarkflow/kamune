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
	ErrInvalidKey       = errors.New("invalid key type")
	ErrInvalidSignature = errors.New("invalid signature")
)

func readKeyData(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrMissingPEM
	}
	return block.Bytes, nil
}

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
