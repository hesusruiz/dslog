package tsaext

import (
	"encoding/asn1"
	"fmt"
)

// OIDLogIndexExtension is the object identifier for the DSLog log index extension.
// This uses an example OID from the private enterprise number arc.
// As per the documentation, you should replace 99999 with your organization's PEN.
var OIDLogIndexExtension = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}

// NewLogIndexExtension creates a new log index extension value.
// It returns the OID and the DER-encoded value suitable for the x509.Extension struct.
func NewLogIndexExtension(logIndex uint64) (asn1.ObjectIdentifier, []byte, error) {
	// The extnValue is the DER-encoded INTEGER.
	extBytes, err := asn1.Marshal(logIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal log index to ASN.1 INTEGER: %w", err)
	}
	return OIDLogIndexExtension, extBytes, nil
}

// ParseLogIndexExtension parses the value of a log index extension.
// The value is expected to be the DER-encoded bytes from the x509.Extension.Value field.
func ParseLogIndexExtension(extValue []byte) (uint64, error) {
	var logIndex uint64
	// The Extension.Value field contains the raw bytes of the DER-encoded INTEGER.
	_, err := asn1.Unmarshal(extValue, &logIndex)
	if err != nil {
		return 0, fmt.Errorf("failed to unmarshal log index from ASN.1 INTEGER: %w", err)
	}
	return logIndex, nil
}
