/*
Package decrypt is the external API other Go programs can use to decrypt SOPS files. It is the only package in SOPS with
a stable API.
*/
package aes // import "github.com/getsops/sops/v3/decrypt"

import (
	"fmt"
	"os"
	"time"

	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	. "github.com/getsops/sops/v3/cmd/sops/formats" // Re-export
	"github.com/getsops/sops/v3/config"
)

// File is a wrapper around Data that reads a local encrypted
// file and returns its cleartext data in an []byte
func File(path, format string) (cleartext []byte, err error) {
	// Read the file into an []byte
	encryptedData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Failed to read %q: %w", path, err)
	}

	// uses same logic as cli.
	formatFmt := FormatForPathOrString(path, format)
	return DataWithFormat(encryptedData, formatFmt, nil)
}

// DataWithFormat is a helper that takes encrypted data, and a format enum value,
// decrypts the data and returns its cleartext in an []byte.
func DataWithFormat(data []byte, format Format, key []byte) (cleartext []byte, err error) {

	store := common.StoreForFormat(format, config.NewStoresConfig())

	// Load SOPS file and access the data key
	tree, err := store.LoadEncryptedFile(data)
	if err != nil {
		return nil, err
	}
	if key == nil {
		key, err = tree.Metadata.GetDataKey()
		if err != nil {
			return nil, err
		}
	}

	// Decrypt the tree
	cipher := aes.NewCipher()
	mac, err := tree.Decrypt(key, cipher)
	if err != nil {
		return nil, err
	}

	// Compute the hash of the cleartext tree and compare it with
	// the one that was stored in the document. If they match,
	// integrity was preserved
	originalMac, err := cipher.Decrypt(
		tree.Metadata.MessageAuthenticationCode,
		key,
		tree.Metadata.LastModified.Format(time.RFC3339),
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to decrypt original mac: %w", err)
	}
	if originalMac != mac {
		return nil, fmt.Errorf("Failed to verify data integrity. expected mac %q, got %q", originalMac, mac)
	}

	return store.EmitPlainFile(tree.Branches)
}

// Data is a helper that takes encrypted data and a format string,
// decrypts the data and returns its cleartext in an []byte.
// The format string can be `json`, `yaml`, `ini`, `dotenv` or `binary`.
// If the format string is empty, binary format is assumed.
func Data(data []byte, format string) (cleartext []byte, err error) {
	formatFmt := FormatFromString(format)
	return DataWithFormat(data, formatFmt, nil)
}
