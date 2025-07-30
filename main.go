package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/rsa" // For rsa.GenerateKey
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/transparency-dev/tessera/client"
	"github.com/transparency-dev/tessera/storage/posix"
	"github.com/transparency-dev/tessera/types" // For STH types

	"go-tsa-tessera/pkg/tsaext"
)

const (
	tsaCertPath          = "tsa.crt"
	tsaKeyPath           = "tsa.key"
	logStoragePath       = "./tessera-log"          // Directory for Tessera POSIX storage
	logCheckpointKeyPath = "log_checkpoint.key"     // Key for signing STHs
	witnessURL           = "http://localhost:8081/add-checkpoint" // Placeholder for ISBE Witness endpoint
	checkpointInterval   = 30 * time.Second         // How often to publish checkpoints (for demonstration)
)

var (
	tsaCert          *x509.Certificate
	tsaPrivKey       crypto.Signer
	tesseraLog       *client.Log    // Tessera log client
	checkpointSigner crypto.Signer  // Key for signing Tessera STHs
)

func loadTSACredentials() error {
	// ... (Same as before) ...
	certPEM, err := os.ReadFile(tsaCertPath)
	if err != nil {
		return fmt.Errorf("failed to read TSA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(tsaKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read TSA private key: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("failed to decode PEM block containing certificate")
	}
	tsaCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	block, _ = pem.Decode(keyPEM)
	if block == nil || (block.Type != "RSA PRIVATE KEY" && block.Type != "EC PRIVATE KEY") {
		return fmt.Errorf("failed to decode PEM block containing private key")
	}
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
	}
	var ok bool
	tsaPrivKey, ok = privKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("private key is not a crypto.Signer")
	}
	return nil
}

func loadCheckpointSigner() error {
    // ... (Same as before) ...
	keyPEM, err := os.ReadFile(logCheckpointKeyPath)
	if err != nil {
		log.Printf("Warning: Checkpoint signing key not found at %s. Generating a new one for development.", logCheckpointKeyPath)
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("failed to generate RSA key for checkpoint signer: %w", err)
		}
		derBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return fmt.Errorf("failed to marshal private key for checkpoint signer: %w", err)
		}
		pemBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: derBytes}
		if err := os.WriteFile(logCheckpointKeyPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
			return fmt.Errorf("failed to write checkpoint private key: %w", err)
		}
		checkpointSigner = priv
		return nil
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil || (block.Type != "RSA PRIVATE KEY" && block.Type != "EC PRIVATE KEY") {
		return fmt.Errorf("failed to decode PEM block containing checkpoint private key")
	}
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse checkpoint private key: %w", err)
		}
	}
	var ok bool
	checkpointSigner, ok = privKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("checkpoint private key is not a crypto.Signer")
	}
	return nil
}

func initializeTesseraLog() error {
	// Create POSIX storage
	s, err := posix.New(logStoragePath)
	if err != nil {
		return fmt.Errorf("failed to create POSIX storage: %w", err)
	}

	// Configure Tessera to use our checkpointSigner
	tesseraLog, err = client.NewLog(s,
		client.WithBatchSize(1), // Process entries immediately for quick index return
		client.WithCheckpointSigner(checkpointSigner, crypto.SHA256), // Use SHA256 for signing STHs
	)
	if err != nil {
		return fmt.Errorf("failed to create Tessera log: %w", err)
	}

	log.Printf("Tessera log initialized at: %s", logStoragePath)
	return nil
}

// publishLatestCheckpoint periodically fetches the latest STH and publishes it to the witness.
func publishLatestCheckpoint() {
	ticker := time.NewTicker(checkpointInterval)
	defer ticker.Stop()

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		sth, err := tesseraLog.LatestCheckpoint(ctx)
		if err != nil {
			log.Printf("Error getting latest checkpoint from Tessera: %v", err)
			cancel() // Ensure context is cancelled on error
			continue
		}
		cancel() // Cancel context after successful retrieval

		if err := submitCheckpointToWitness(sth); err != nil {
			log.Printf("Error submitting checkpoint to witness: %v", err)
		} else {
			log.Printf("Checkpoint published to witness: treeSize=%d, rootHash=%x", sth.Size, sth.RootHash)
		}
	}
}

// submitCheckpointToWitness sends the STH to the ISBE Witness component.
// This is a conceptual implementation and needs to be replaced with actual
// HTTP client code conforming to the Transparency Log Witness Protocol.
func submitCheckpointToWitness(sth *types.SignedTreeHead) error {
	// This is where you would implement the client-side of the Transparency Log Witness Protocol.
	// 1. Marshal the STH and relevant log metadata into the "Transparency Log Checkpoint" format
	//    defined at https://github.com/C2SP/C2SP/blob/main/tlog-witness.md.
	// 2. Make an HTTP POST request to the witnessURL, sending the marshaled checkpoint.
	// 3. Handle the witness's response (e.g., timestamped cosignature) and verify it.

	// Example placeholder for the data format to send to the witness.
	// You'd need a struct that matches the witness protocol's input, e.g.:
	/*
	type WitnessCheckpointRequest struct {
		LogID        []byte `json:"log_id"` // Hash of the log's public key
		SignedTreeHead *types.SignedTreeHead `json:"signed_tree_head"`
		// ... potentially other metadata like log's public key
	}
	reqData := WitnessCheckpointRequest{
		// Populate this from your log's config and the STH
		// Example: LogID should be a consistent identifier for *this* log instance
		SignedTreeHead: sth,
	}
	jsonData, err := json.Marshal(reqData)
	if err != nil { return fmt.Errorf("failed to marshal witness request: %w", err) }

	resp, err := http.Post(witnessURL, "application/json", bytes.NewReader(jsonData))
	if err != nil { return fmt.Errorf("failed to send checkpoint to witness: %w", err) }
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("witness returned non-OK status %d: %s", resp.StatusCode, string(bodyBytes))
	}
	// Parse and verify the cosignature from the witness response if needed
	*/

	log.Printf("Simulating submission of checkpoint to ISBE Witness: STH (TreeSize: %d, RootHash: %x)", sth.Size, sth.RootHash)
	return nil // Simulate success
}

func tsaHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	reqBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	tsReq, err := timestamp.ParseRequest(reqBytes)
	if err != nil {
		log.Printf("Error parsing TimeStampReq: %v", err)
		respErr, _ := timestamp.CreateResponse(nil, nil,
			timestamp.WithStatus(timestamp.PKIStatusRejection, timestamp.FailureInfoBadRequest),
		)
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(respErr)
		return
	}

	log.Printf("Received TimeStampReq for message imprint: %x (Nonce: %s)",
		tsReq.MessageImprint.HashedMessage, tsReq.Nonce.String())

	// The entry in the log is the client's original RFC 3161 request.
	entry := client.NewEntry(reqBytes)

	logIndex, err := tesseraLog.Add(context.Background(), entry)
	if err != nil {
		log.Printf("Error adding entry to Tessera log: %v", err)
		respErr, _ := timestamp.CreateResponse(nil, nil,
			timestamp.WithStatus(timestamp.PKIStatusRejection, timestamp.FailureInfoSystemFailure),
		)
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(respErr)
		return
	}
	log.Printf("Request logged to Tessera at index: %d", logIndex)

	oid, extBytes, err := tsaext.NewLogIndexExtension(logIndex)
	if err != nil {
		log.Printf("Error creating log index extension: %v", err)
		respErr, _ := timestamp.CreateResponse(nil, nil,
			timestamp.WithStatus(timestamp.PKIStatusRejection, timestamp.FailureInfoSystemFailure),
		)
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(respErr)
		return
	}

	opts := &timestamp.ResponseOpts{
		Extensions: []x509.Extension{
			{
				Id:       oid,
				Critical: false,
				Value:    extBytes,
			},
		},
	}

	tsResp, err := tsReq.CreateResponseWithOpts(tsaCert, tsaPrivKey, opts)
	if err != nil {
		log.Printf("Error creating TimeStampResp: %v", err)
		respErr, _ := timestamp.CreateResponse(nil, nil,
			timestamp.WithStatus(timestamp.PKIStatusRejection, timestamp.FailureInfoSystemFailure),
		)
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(respErr)
		return
	}

	w.Header().Set("Content-Type", "application/timestamp-reply")
	w.Write(tsResp)
}


func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if err := loadTSACredentials(); err != nil {
		log.Fatalf("Failed to load TSA credentials: %v", err)
	}
	log.Println("TSA credentials loaded successfully.")

    if err := loadCheckpointSigner(); err != nil {
        log.Fatalf("Failed to load/generate checkpoint signer: %v", err)
    }
    log.Println("Checkpoint signer loaded/generated.")

	if err := initializeTesseraLog(); err != nil {
		log.Fatalf("Failed to initialize Tessera log: %v", err)
	}
	log.Println("Tessera log initialized.")

	// Start a goroutine to periodically publish checkpoints
	go publishLatestCheckpoint()

	http.HandleFunc("/tsa", tsaHandler)

	addr := ":8080"
	log.Printf("TSA server listening on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
