package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"time"
)

// --- ASN.1 Structures for RFC 3161 ---

// OID for Time-Stamp Protocol
var oidTSP = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16}

// Custom OID for a placeholder "index" extension.
// TODO: Try to register an OID for this.
var oidExtensionIndex = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}

// TimeStampRequest
type TimeStampRequest struct {
	Version        int
	MessageImprint MessageImprint
	Nonce          *big.Int        `asn1:"optional"`
	CertReq        bool            `asn1:"optional"`
	Extensions     []asn1.RawValue `asn1:"tag:3,optional,explicit"`
}

// MessageImprint
type MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// TimeStampResponse
type TimeStampResponse struct {
	Status         PKIStatusInfo
	TimeStampToken *asn1.RawValue `asn1:"optional"`
}

// PKIStatusInfo
type PKIStatusInfo struct {
	Status       int
	StatusString []string       `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// SignedData is part of the CMS structure for the TimeStampToken
type SignedData struct {
	Version                 int
	DigestAlgorithms        []pkix.AlgorithmIdentifier
	EncapsulatedContentInfo ContentInfo
	Certificates            asn1.RawValue `asn1:"tag:0,optional,explicit"`
	CRLs                    asn1.RawValue `asn1:"tag:1,optional,explicit"`
	SignerInfos             []SignerInfo
}

// ContentInfo
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

// SignerInfo
type SignerInfo struct {
	Version            int
	Sid                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"tag:0,optional,explicit"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"tag:1,optional,explicit"`
}

// TSTInfo contains the actual timestamp information
type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier `asn1:"optional"`
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time
	Accuracy       Accuracy      `asn1:"optional"`
	Nonce          *big.Int      `asn1:"optional"`
	Ordering       bool          `asn1:"optional"`
	TSA            asn1.RawValue `asn1:"tag:0,optional,explicit"`
	Extensions     asn1.RawValue `asn1:"tag:1,optional,explicit"`
}

// Accuracy
type Accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"tag:0,optional"`
	Micros  int `asn1:"tag:1,optional"`
}

// --- Certificate and Key Generation ---

// generateSelfSignedCert generates a self-signed RSA key pair and a
// certificate for the timestamp server. In a production environment,
// you would use a CA-signed certificate.
func generateSelfSignedCert() (*x509.Certificate, crypto.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Gemini Timestamp Service"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, key, nil
}

// --- Main Handler Function ---

// timestampHandler handles incoming RFC 3161 timestamp requests.
func timestampHandler(w http.ResponseWriter, r *http.Request, cert *x509.Certificate, key crypto.PrivateKey) {
	// Ensure the request method is POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	// Parse the TimeStampRequest from the ASN.1 encoded body
	var tsr TimeStampRequest
	_, err = asn1.Unmarshal(body, &tsr)
	if err != nil {
		log.Printf("Failed to unmarshal TimeStampRequest: %v", err)
		http.Error(w, "Invalid TimeStampRequest format", http.StatusBadRequest)
		return
	}

	// Add the custom extension
	// For this example, we'll just add a hardcoded index value.
	// A real implementation might use a database-driven sequence.
	indexValue := 12345
	indexExtensionBytes, err := asn1.Marshal(indexValue)
	if err != nil {
		log.Printf("Failed to marshal index value for extension: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create the extension as a pkix.Extension
	// It is non-critical, so if the client does not understand this extension, it can still process the timestamp.
	indexExtension := pkix.Extension{
		Id:       oidExtensionIndex,
		Critical: false,
		Value:    indexExtensionBytes,
	}

	// Create a slice of extensions and marshal it to create the extensions field.
	// This will be a SEQUENCE OF Extension.
	extensionsBytes, err := asn1.Marshal([]pkix.Extension{indexExtension})
	if err != nil {
		log.Printf("Failed to marshal extensions: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create the TSTInfo (TimeStampToken info)
	tstInfo := TSTInfo{
		Version:        1,
		Policy:         oidTSP, // Using the default policy OID
		MessageImprint: tsr.MessageImprint,
		SerialNumber:   big.NewInt(time.Now().UnixNano()), // Unique serial number
		GenTime:        time.Now().UTC(),
		Accuracy: Accuracy{
			Seconds: 0,
			Millis:  1,
			Micros:  0,
		},
		Nonce:    tsr.Nonce,
		Ordering: false,
		Extensions: asn1.RawValue{
			Tag:        1,
			Class:      asn1.ClassContextSpecific,
			IsCompound: true,
			Bytes:      extensionsBytes,
		},
	}

	tstInfoBytes, err := asn1.Marshal(tstInfo)
	if err != nil {
		log.Printf("Failed to marshal TSTInfo: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Sign the TSTInfo
	// Create a SHA-256 hash of the TSTInfo bytes
	hashed := sha256.Sum256(tstInfoBytes)

	// Sign the hash with the private key
	signature, err := rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, hashed[:])
	if err != nil {
		log.Printf("Failed to sign TSTInfo: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// --- Build the TimeStampToken (CMS SignedData) ---

	// Prepare signer info
	signerInfo := SignerInfo{
		Version: 1,
		Sid: asn1.RawValue{
			Tag:        0, // IssuerAndSerialNumber
			IsCompound: true,
			Class:      asn1.ClassContextSpecific,
			Bytes:      []byte{}, // We won't be using a full IssuerAndSerialNumber for this example
		},
		DigestAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, // SHA-256
		},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, // RSA-SHA256
		},
		Signature: signature,
	}

	// The ContentInfo for the actual TSTInfo
	tstInfoContent, err := asn1.Marshal(tstInfo)
	if err != nil {
		log.Printf("Failed to marshal TSTInfo content: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	contentInfo := ContentInfo{
		ContentType: oidTSP,
		Content: asn1.RawValue{
			Tag:        0,
			Class:      asn1.ClassContextSpecific,
			IsCompound: true,
			Bytes:      tstInfoContent,
		},
	}

	// SignedData structure
	signedData := SignedData{
		Version: 1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{
			{
				Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, // SHA-256
			},
		},
		EncapsulatedContentInfo: contentInfo,
		Certificates: asn1.RawValue{
			Tag:        0,
			IsCompound: true,
			Class:      asn1.ClassContextSpecific,
			Bytes:      cert.Raw,
		},
		SignerInfos: []SignerInfo{signerInfo},
	}

	signedDataBytes, err := asn1.Marshal(signedData)
	if err != nil {
		log.Printf("Failed to marshal SignedData: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Final TimeStampToken (CMS) structure
	timeStampToken := ContentInfo{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}, // SignedData OID
		Content: asn1.RawValue{
			Tag:        0,
			Class:      asn1.ClassContextSpecific,
			IsCompound: true,
			Bytes:      signedDataBytes,
		},
	}

	timeStampTokenBytes, err := asn1.Marshal(timeStampToken)
	if err != nil {
		log.Printf("Failed to marshal TimeStampToken: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	rawToken := asn1.RawValue{
		Tag:        0,
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Bytes:      timeStampTokenBytes,
	}

	// --- Build the final TimeStampResponse ---
	tsrResp := TimeStampResponse{
		Status: PKIStatusInfo{
			Status: 0, // PKIStatus: Granted
		},
		TimeStampToken: &rawToken,
	}

	tsrRespBytes, err := asn1.Marshal(tsrResp)
	if err != nil {
		log.Printf("Failed to marshal TimeStampResponse: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set the content type and write the response
	w.Header().Set("Content-Type", "application/timestamp-response")
	w.Write(tsrRespBytes)
}

func main() {
	// Generate a self-signed certificate and private key for the server.
	// TODO: use a real eIDAS certificate and sign securely, either with HSM or via Remote CSC API 2.0.
	cert, key, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate server certificate: %v", err)
	}

	// Create a handler function with the generated cert and key
	handlerFunc := func(w http.ResponseWriter, r *http.Request) {
		timestampHandler(w, r, cert, key)
	}

	http.HandleFunc("/", handlerFunc)

	log.Println("RFC 3161 Timestamp Server listening on :8080...")
	log.Println("To test, use a tool like 'openssl' or 'curl' to send a POST request with an RFC 3161 query.")
	log.Println("Example curl command (requires a file to hash, e.g., my_file.txt):")
	log.Println("  openssl ts -query -data my_file.txt -no_nonce -sha256 -out ts_request.tsq")
	log.Println("  curl -X POST -H 'Content-Type: application/timestamp-query' --data-binary @ts_request.tsq http://localhost:8080 > ts_response.tsr")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// --- Example usage functions (not part of the server, for testing) ---

// This function creates a simple RFC 3161 request for a given hash.
// This is for demonstration and testing purposes.
func createRequestForHash(hash []byte) ([]byte, error) {
	// OID for SHA-256
	oidSHA256 := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

	tsr := TimeStampRequest{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: oidSHA256,
			},
			HashedMessage: hash,
		},
		Nonce:   big.NewInt(123456789),
		CertReq: true,
	}

	return asn1.Marshal(tsr)
}

// This function can be used to manually test the server
func testServer() {
	// A simple SHA-256 hash of "Hello World"
	h := sha256.New()
	h.Write([]byte("Hello World"))
	hash := h.Sum(nil)

	requestBytes, err := createRequestForHash(hash)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	resp, err := http.Post("http://localhost:8080", "application/timestamp-query", bytes.NewReader(requestBytes))
	if err != nil {
		log.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("Server returned error: %d, body: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	var tsrResp TimeStampResponse
	_, err = asn1.Unmarshal(body, &tsrResp)
	if err != nil {
		log.Fatalf("Failed to unmarshal TimeStampResponse: %v", err)
	}

	log.Printf("Received successful timestamp response with status: %d", tsrResp.Status.Status)
}
