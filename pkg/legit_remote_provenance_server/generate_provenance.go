package legit_remote_provenance_server

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

type ProvenanceGenerator interface {
	GenerateSignedProvenance(remoteAttestationData legit_remote_provenance.RemoteAttestationData) ([]byte, error)
}

type provenanceGenerator struct {
	ctx                     context.Context
	keyRef                  string
	provenanceGeneratorPath string
}

func NewProvenanceGenerator(ctx context.Context, keyRef string) ProvenanceGenerator {
	return &provenanceGenerator{
		ctx:                     ctx,
		keyRef:                  keyRef,
		provenanceGeneratorPath: PROVENANCE_GENERATOR_PATH,
	}
}

func (p *provenanceGenerator) GenerateSignedProvenance(remoteAttestationData legit_remote_provenance.RemoteAttestationData) ([]byte, error) {
	provenance, err := p.generateProvenance(remoteAttestationData)
	if err != nil {
		return nil, err
	}

	signed, err := p.signProvenance(provenance)
	if err != nil {
		return nil, err
	}

	return signed, nil
}

func (p *provenanceGenerator) generateProvenance(remoteAttestationData legit_remote_provenance.RemoteAttestationData) ([]byte, error) {
	if err := remoteAttestationData.ApplyToEnv(); err != nil {
		return nil, fmt.Errorf("failed to apply env: %v", err)
	}

	output, err := cmdExec(p.provenanceGeneratorPath, "attest",
		"--subjects", remoteAttestationData.SubjectsBase64,
		"--unsigned-to-stdout")

	if err != nil {
		return nil, fmt.Errorf("failed to generate provenance: %v", err)
	}

	return output, nil
}

func (p *provenanceGenerator) signProvenance(provenance []byte) ([]byte, error) {
	signed, err := legit_attest.Attest(p.ctx, p.keyRef, provenance)
	if err != nil {
		return nil, fmt.Errorf("failed to sign attestation: %v", err)
	}

	return signed, nil
}

func cmdExec(args ...string) ([]byte, error) {
	baseCmd := args[0]
	cmdArgs := args[1:]

	cmd := exec.Command(baseCmd, cmdArgs...)
	cmd.Stderr = os.Stderr

	output, err := cmd.Output()
	return output, err
}
