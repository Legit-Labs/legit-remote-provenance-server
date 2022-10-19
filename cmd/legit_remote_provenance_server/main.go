package main

import (
	"context"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"os"

	"github.com/legit-labs/legit-remote-provenance-server/pkg/legit_remote_provenance_server"
	"github.com/legit-labs/legit-remote-provenance/pkg/legit_remote_provenance"
)

var (
	keyPath               string
	jwtB64                string
	remoteAttestationData string
	verifyJwt             bool
)

func main() {
	flag.StringVar(&keyPath, "key", "", "The path of the private key")
	flag.StringVar(&jwtB64, "jwt-base64", "", "The base64-encoded JWT token")
	flag.BoolVar(&verifyJwt, "verify-jwt", false, "Verify the validity of the JWT token (default false)")

	flag.Parse()

	if keyPath == "" {
		log.Panicf("please provide a private key path")
	} else if jwtB64 == "" {
		log.Panicf("please provide a JWT token")
	}

	remoteAttestationDataJson, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Panicf("failed to read remote attestation data from stdin")
	}
	var attestationData legit_remote_provenance.RemoteAttestationData
	if err := json.Unmarshal(remoteAttestationDataJson, &attestationData); err != nil {
		log.Panicf("failed to unrmarshal remote attestation data")
	}

	ctx := context.Background()

	verifier := legit_remote_provenance_server.NewJwtVerifier(verifyJwt)
	if err := verifier.Verify(jwtB64); err != nil {
		log.Panicf("failed to verify jwt token")
	}

	pg := legit_remote_provenance_server.NewProvenanceGenerator(ctx, keyPath)
	signedProv, err := pg.GenerateSignedProvenance(attestationData)
	if err != nil {
		log.Fatalf("failed to generate provenance: %v", err)
	}

	os.Stdout.Write(signedProv)
}
