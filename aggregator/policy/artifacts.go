package policy

import (
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	cs "github.com/consensys/gnark/constraint/bn254"
)

//go:embed data/sp1_groth16_vk.bin
var sp1Groth16VK []byte

//go:embed data/risc0_groth16_vk.bin
var risc0Groth16VK []byte

const (
	fileProof          = "proof.bin"
	filePublicValues   = "public_values.bin"
	fileVkeyHash       = "vkey_hash.txt"
	fileSeal           = "seal.bin"
	fileClaimDigest    = "claim_digest.bin"
	fileControlRoot    = "control_root.bin"
	fileBn254ControlID = "bn254_control_id.bin"
	filePreDigest      = "pre_digest.bin"

	outerCCSFile   = "outer_ccs.bin"
	outerPKFile    = "outer_pk.bin"
	outerVKFile    = "outer_vk.bin"
	outerProofFile = "outer_proof.bin"
	fileFrostOut   = "frost_outputs.bin"
)

type BackendID string

const (
	BackendSP1   BackendID = "sp1"
	BackendRISC0 BackendID = "risc0"
	BackendJolt  BackendID = "jolt"
)

type BindingKind uint8

const (
	BindingNone BindingKind = iota
	BindingSP1Digest
	BindingPinPublic
)

type SlotSpec struct {
	Backend BackendID
	Binding BindingKind
}

type Policy struct {
	Threshold int
	Slots     []SlotSpec
}

var DefaultPolicy = Policy{
	Threshold: 2,
	Slots: []SlotSpec{
		{BackendSP1, BindingSP1Digest},
		{BackendRISC0, BindingPinPublic},
		{BackendSP1, BindingNone},
	},
}

type outerArtifacts struct {
	CCS *cs.R1CS
	PK  groth16.ProvingKey
	VK  groth16.VerifyingKey
}

func readBin(dir, name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return b, nil
}

func readFixedLen(path string, want int) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) != want {
		return nil, fmt.Errorf("want %d bytes, got %d", want, len(b))
	}
	return b, nil
}

func readDigest32(path string) ([32]byte, error) {
	b, err := readFixedLen(path, 32)
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

func loadOuterArtifacts(dir string) (*outerArtifacts, error) {
	var ccs cs.R1CS
	if err := readFile(filepath.Join(dir, outerCCSFile), ccs.ReadFrom); err != nil {
		return nil, fmt.Errorf("outer ccs: %w", err)
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if err := readFile(filepath.Join(dir, outerPKFile), pk.ReadFrom); err != nil {
		return nil, fmt.Errorf("outer pk: %w", err)
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if err := readFile(filepath.Join(dir, outerVKFile), vk.ReadFrom); err != nil {
		return nil, fmt.Errorf("outer vk: %w", err)
	}
	return &outerArtifacts{CCS: &ccs, PK: pk, VK: vk}, nil
}

func saveOuterArtifacts(dir string, ccs *cs.R1CS, pk groth16.ProvingKey, vk groth16.VerifyingKey) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, item := range []struct {
		name  string
		write func(io.Writer) (int64, error)
	}{
		{outerCCSFile, ccs.WriteTo},
		{outerPKFile, pk.WriteTo},
		{outerVKFile, vk.WriteTo},
	} {
		if err := writeFile(filepath.Join(dir, item.name), item.write); err != nil {
			return err
		}
	}
	return nil
}

func saveOuter(outDir string, proof groth16.Proof, vk groth16.VerifyingKey, frost []byte) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(outDir, outerProofFile), proof.WriteTo); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(outDir, outerVKFile), vk.WriteTo); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, fileFrostOut), frost, 0o644)
}

func writeFile(path string, fn func(io.Writer) (int64, error)) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}()
	_, err = fn(f)
	return err
}

func readFile(path string, fn func(io.Reader) (int64, error)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fn(f)
	return err
}
