package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/legit-labs/legit-attestation/pkg/legit_attest"
	"github.com/legit-labs/legit-remote-provenance/pkg/legit_remote_provenance"
)

const (
	PROVENANCE_GENERATOR_PATH = "./generator"
)

func cmdExec(args ...string) ([]byte, error) {
	baseCmd := args[0]
	cmdArgs := args[1:]

	cmd := exec.Command(baseCmd, cmdArgs...)
	cmd.Stderr = os.Stderr

	output, err := cmd.Output()
	return output, err
}

func GenerateSignedProvenance(ctx context.Context, keyRef string, remoteAttestationData legit_remote_provenance.RemoteAttestationData) ([]byte, error) {
	provenance, err := generateProvenance(remoteAttestationData)
	if err != nil {
		return nil, err
	}

	signed, err := signProvenance(ctx, keyRef, provenance)
	if err != nil {
		return nil, err
	}

	return signed, nil
}

func generateProvenance(remoteAttestationData legit_remote_provenance.RemoteAttestationData) ([]byte, error) {
	if err := remoteAttestationData.ApplyToEnv(); err != nil {
		return nil, fmt.Errorf("failed to apply env: %v", err)
	}

	output, err := cmdExec(PROVENANCE_GENERATOR_PATH, "attest", "--subjects", remoteAttestationData.SubjectsBase64, "--unsigned-to-stdout")
	if err != nil {
		return nil, fmt.Errorf("failed to generate provenance: %v", err)
	}

	return output, nil
}

func signProvenance(ctx context.Context, keyRef string, provenance []byte) ([]byte, error) {
	signed, err := legit_attest.Attest(ctx, keyRef, provenance)
	if err != nil {
		return nil, fmt.Errorf("failed to sign attestation: %v", err)
	}

	return signed, nil
}
