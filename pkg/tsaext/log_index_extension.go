package tsaext

import (
	"encoding/asn1"
	"fmt"
	"math/big"
)

// OID for our custom log index extension.
// This is a placeholder; in a real-world scenario, you'd register your own Private Enterprise Number (PEN)
// or use a designated OID for your application.
var OIDLogIndexExtension = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1} // Example PEN 99999, custom extension 1

// LogIndexExtension represents the structure for our custom extension payload.
// It simply holds the log index as an INTEGER.
type LogIndexExtension struct {
	Index *big.Int
}

// NewLogIndexExtension creates a pkix.Extension for the given log index.
func NewLogIndexExtension(index uint64) (asn1.ObjectIdentifier, []byte, error) {
	extData := LogIndexExtension{
		Index: big.NewInt(int64(index)),
	}

	extBytes, err := asn1.Marshal(extData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal log index extension: %w", err)
	}

	return OIDLogIndexExtension, extBytes, nil
}

// ParseLogIndexExtension parses the raw extension bytes and returns the log index.
func ParseLogIndexExtension(extBytes []byte) (uint64, error) {
	var extData LogIndexExtension
	_, err := asn1.Unmarshal(extBytes, &extData)
	if err != nil {
		return 0, fmt.Errorf("failed to unmarshal log index extension: %w", err)
	}
	if !extData.Index.IsUint64() {
		return 0, fmt.Errorf("log index is too large to fit in uint64")
	}
	return extData.Index.Uint64(), nil
}
