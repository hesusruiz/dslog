# DSLog Developer Quick-Start Guide

This guide provides a hands-on, step-by-step walkthrough for developers to interact with a DSLog service using Go. You will learn how to:

1.  Prepare data and create a standard RFC 3161 timestamp request.
2.  Send the request to a DSLog endpoint.
3.  Parse the response and extract the critical `logIndex`.
4.  Understand the two-part verification process: standard signature validation and proof-of-inclusion verification.

## Prerequisites

*   Go programming language (1.18+).
*   Basic understanding of hashing (SHA-256).
*   Familiarity with making HTTP requests in Go.

We will use the excellent `github.com/digitorus/timestamp` library for handling RFC 3161 structures.

```bash
go get github.com/digitorus/timestamp
```

## Step 1: Prepare Your Data

The first step is to create a cryptographic hash of the data you want to timestamp. The DSLog service never sees your raw data, only this hash.

```go
package main

import (
	"crypto/sha256"
	"fmt"
)

func main() {
	// The data you want to prove existed at a certain time.
	data := []byte("This is the content of my very important document.")

	// Hash the data using SHA-256.
	hasher := sha256.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	fmt.Printf("Data Digest (SHA-256): %x\n", digest)
}
```

## Step 2: Create the Timestamp Request

Using the digest from Step 1, create a standard RFC 3161 `TimeStampReq`.

```go
import "github.com/digitorus/timestamp"

// ... inside main() ...

tsq, err := timestamp.CreateRequest(digest, &timestamp.RequestOptions{
	Certificates: true, // Request the TSA's signing certificate in the response
})
if err != nil {
	// Handle error
}

// tsq is a []byte slice containing the DER-encoded request.
```

## Step 3: Send the Request to the DSLog Service

Send the `TimeStampReq` bytes to the DSLog TSA endpoint via an HTTP POST request.

```go
import (
	"bytes"
	"net/http"
)

// ... inside main() ...

dslogTsaURL := "https://dslog.example.com/tsa" // Replace with the actual DSLog endpoint

resp, err := http.Post(dslogTsaURL, "application/timestamp-query", bytes.NewReader(tsq))
if err != nil {
	// Handle error
}
defer resp.Body.Close()

if resp.StatusCode != http.StatusOK {
	// Handle non-200 status code
}
```

## Step 4: Parse the Response and Extract the Log Index

The response body contains the `TimeStampResp`. We need to parse it to get the `TimeStampToken` and, most importantly, the custom `logIndex` extension.

```go
import (
	"io"
	"encoding/asn1"
)

// ... inside main() ...

respBytes, err := io.ReadAll(resp.Body)
if err != nil {
	// Handle error
}

tsr, err := timestamp.ParseResponse(respBytes)
if err != nil {
	// Handle error
}

// The OID for the log index extension. Replace with the one used by your DSLog provider.
var oidLogIndex = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}
var logIndex int64 = -1

for _, ext := range tsr.TimeStampToken.TSTInfo.Extensions {
	if ext.Id.Equal(oidLogIndex) {
		// The extension value is a DER-encoded INTEGER.
		_, err := asn1.Unmarshal(ext.Value, &logIndex)
		if err != nil {
			// Handle parsing error
		}
		break
	}
}

if logIndex != -1 {
	fmt.Printf("Success! Timestamp received and entry logged at index: %d\n", logIndex)
} else {
	fmt.Println("Warning: Log index extension not found in the response.")
}

// You should now securely store:
// 1. Your original data (or its hash)
// 2. The full TimeStampToken (tsr.TimeStampToken)
// 3. The extracted logIndex
```

## Step 5: Verification (The DSLog Advantage)

Verification is a two-part process that provides complete trust.

### Part A: Standard RFC 3161 Verification

First, verify the TSA's signature on the timestamp token. This proves that the specific TSA issued a timestamp for your data hash at a specific time.

```go
// Verify the timestamp token against the original request.
// This checks the signature, nonce, hash, etc.
err = tsr.TimeStampToken.Verify(tsq)
if err != nil {
	fmt.Printf("Standard RFC 3161 verification failed: %v\n", err)
} else {
	fmt.Println("Standard RFC 3161 verification successful!")
}
```

### Part B: Verifying Proof of Inclusion

This is the crucial step that DSLog adds. It proves that your timestamp was not just issued but was also included in the public, globally consistent, and tamper-evident log.

This process is more involved and typically handled by a dedicated client library. The conceptual steps are:
1.  **Get a Trusted Checkpoint:** Retrieve a recent Signed Tree Head (STH) from the ISBE Blockchain. This STH is the "root of trust" and contains a `TreeSize` and a `RootHash`.
2.  **Fetch Log Tiles:** Using your `logIndex` and the `TreeSize` from the STH, calculate which Merkle tree "tiles" you need to download from the log's public tile server.
3.  **Reconstruct and Verify:** Download the tiles and use them to locally reconstruct the Merkle path from your entry's leaf hash all the way up to the root. If the calculated root matches the `RootHash` in the trusted STH, your proof of inclusion is valid.

For a detailed explanation of this flow, please refer to the main **DSLog Architecture Document**.