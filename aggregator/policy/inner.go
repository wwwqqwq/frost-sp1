package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	bn254groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
)

const (
	groth16ProofLen   = 256
	sp1ProofPrefixLen = 100
)

func parseGroth16VK(b []byte) (groth16.VerifyingKey, error) {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(bytes.NewReader(b)); err != nil {
		return nil, fmt.Errorf("groth16 vk: %w", err)
	}
	return vk, nil
}

type innerProof struct {
	vk            groth16.VerifyingKey
	proof         groth16.Proof
	publicValues  []byte
	publicWitness witness.Witness
}

type Loaded struct {
	Proof        innerProof
	publicInputs []fr.Element
	preDigest    [32]byte
}

func frToBig(element fr.Element) *big.Int {
	var value big.Int
	element.BigInt(&value)
	return &value
}

type backendLoader func(dir string) (*Loaded, error)

var backendLoaders = map[BackendID]backendLoader{
	BackendSP1:   loadSP1,
	BackendRISC0: loadRISC0,
}

func loadForPolicy(dirs map[BackendID]string, pol Policy) (map[BackendID]*Loaded, error) {
	need := map[BackendID]bool{}
	for _, slot := range pol.Slots {
		if slot.Binding == BindingNone {
			continue
		}
		need[slot.Backend] = true
	}
	out := make(map[BackendID]*Loaded, len(need))
	var ref []byte
	for id := range need {
		dir, ok := dirs[id]
		if !ok || dir == "" {
			return nil, fmt.Errorf("backend %q: dump dir required", id)
		}
		load, ok := backendLoaders[id]
		if !ok {
			return nil, fmt.Errorf("backend %q: not registered (add loader + vk embed)", id)
		}
		l, err := load(dir)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", id, err)
		}
		if ref == nil {
			ref = l.Proof.publicValues
		} else if !bytes.Equal(ref, l.Proof.publicValues) {
			return nil, fmt.Errorf("backend %q: %s mismatch with other inner proofs", id, filePublicValues)
		}
		out[id] = l
	}
	return out, nil
}

func loadSP1(dir string) (*Loaded, error) {
	proofBytes, err := readBin(dir, fileProof)
	if err != nil {
		return nil, err
	}
	publicValues, err := readFixedLen(filepath.Join(dir, filePublicValues), ProofOutputsLen)
	if err != nil {
		return nil, err
	}
	vkeyHash, err := readBin(dir, fileVkeyHash)
	if err != nil {
		return nil, err
	}
	if len(proofBytes) < sp1ProofPrefixLen+groth16ProofLen {
		return nil, fmt.Errorf("%s: too short", fileProof)
	}
	vkBytes := sp1Groth16VK
	vkSum := sha256.Sum256(vkBytes)
	if !bytes.Equal(vkSum[:4], proofBytes[:4]) {
		return nil, fmt.Errorf("vk hash prefix mismatch")
	}
	vk, err := parseGroth16VK(vkBytes)
	if err != nil {
		return nil, err
	}
	dec := curve.NewDecoder(bytes.NewReader(proofBytes[sp1ProofPrefixLen : sp1ProofPrefixLen+groth16ProofLen]))
	var p bn254groth16.Proof
	if err := dec.Decode(&p.Ar); err != nil {
		return nil, fmt.Errorf("proof A: %w", err)
	}
	if err := dec.Decode(&p.Bs); err != nil {
		return nil, fmt.Errorf("proof B: %w", err)
	}
	if err := dec.Decode(&p.Krs); err != nil {
		return nil, fmt.Errorf("proof C: %w", err)
	}
	vh, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(string(vkeyHash)), "0x"))
	if err != nil || len(vh) != 32 {
		return nil, fmt.Errorf("bad %s", fileVkeyHash)
	}
	h := sha256.Sum256(publicValues)
	h[0] &= 0x1F
	inputs := []fr.Element{
		frFromBytes(vh),
		frFromBytes(h[:]),
		frFromBytes(proofBytes[4:36]),
		frFromBytes(proofBytes[36:68]),
		frFromBytes(proofBytes[68:sp1ProofPrefixLen]),
	}
	w, err := publicWitness(inputs)
	if err != nil {
		return nil, err
	}
	return &Loaded{
		Proof:        innerProof{vk, &p, publicValues, w},
		publicInputs: inputs,
	}, nil
}

func loadRISC0(dir string) (*Loaded, error) {
	seal, err := readBin(dir, fileSeal)
	if err != nil {
		return nil, err
	}
	publicValues, err := readFixedLen(filepath.Join(dir, filePublicValues), ProofOutputsLen)
	if err != nil {
		return nil, err
	}
	claim, err := readDigest32(filepath.Join(dir, fileClaimDigest))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fileClaimDigest, err)
	}
	controlRoot, err := readDigest32(filepath.Join(dir, fileControlRoot))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fileControlRoot, err)
	}
	bn254ControlID, err := readDigest32(filepath.Join(dir, fileBn254ControlID))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fileBn254ControlID, err)
	}
	preDigest, err := readDigest32(filepath.Join(dir, filePreDigest))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filePreDigest, err)
	}
	vkBytes := risc0Groth16VK
	vk, err := parseGroth16VK(vkBytes)
	if err != nil {
		return nil, err
	}
	proof, err := sealToProof(seal)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fileSeal, err)
	}
	pins := risc0PublicInputs(controlRoot, claim, bn254ControlID)
	w, err := publicWitness(pins)
	if err != nil {
		return nil, err
	}
	return &Loaded{
		Proof:        innerProof{vk, proof, publicValues, w},
		publicInputs: pins,
		preDigest:    preDigest,
	}, nil
}

func frFromBytes(b []byte) fr.Element {
	var e fr.Element
	e.SetBytes(b)
	return e
}

func publicWitness(inputs []fr.Element) (witness.Witness, error) {
	w, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	ch := make(chan any, len(inputs))
	for i := range inputs {
		ch <- inputs[i]
	}
	close(ch)
	return w, w.Fill(len(inputs), 0, ch)
}

func risc0PublicInputs(controlRoot, claimDigest, bn254ControlID [32]byte) []fr.Element {
	a0, a1 := splitDigest(controlRoot)
	c0, c1 := splitDigest(claimDigest)
	rev := reverse32(bn254ControlID)
	return []fr.Element{a0, a1, c0, c1, frFromRisc0ScalarBytes(rev[:])}
}

func splitDigest(d [32]byte) (fr.Element, fr.Element) {
	be := reverse32(d)
	return frFromRisc0ScalarBytes(be[16:32]), frFromRisc0ScalarBytes(be[0:16])
}

func reverse32(d [32]byte) [32]byte {
	var out [32]byte
	for i := range d {
		out[i] = d[31-i]
	}
	return out
}

func frFromRisc0ScalarBytes(raw []byte) fr.Element {
	var fixed [32]byte
	copy(fixed[32-len(raw):], raw)
	var e fr.Element
	e.SetBytes(fixed[:])
	return e
}

func sealToProof(seal []byte) (groth16.Proof, error) {
	if len(seal) != groth16ProofLen {
		return nil, fmt.Errorf("want %d bytes, got %d", groth16ProofLen, len(seal))
	}
	const w = 32
	ar := g1FromSealBE(seal[0:w], seal[w:2*w])
	off := 2 * w
	bs, err := g2FromRisc0Seal(seal[off:off+w], seal[off+w:off+2*w], seal[off+2*w:off+3*w], seal[off+3*w:off+4*w])
	if err != nil {
		return nil, fmt.Errorf("B: %w", err)
	}
	off += 4 * w
	krs := g1FromSealBE(seal[off:off+w], seal[off+w:off+2*w])
	return &bn254groth16.Proof{Ar: ar, Bs: bs, Krs: krs}, nil
}

func g1FromSealBE(xBytes, yBytes []byte) curve.G1Affine {
	var p curve.G1Affine
	p.X.SetBigInt(new(big.Int).SetBytes(xBytes))
	p.Y.SetBigInt(new(big.Int).SetBytes(yBytes))
	return p
}

func g2FromRisc0Seal(x00, x01, x10, x11 []byte) (curve.G2Affine, error) {
	var p curve.G2Affine
	p.X.A1.SetBigInt(new(big.Int).SetBytes(x00))
	p.X.A0.SetBigInt(new(big.Int).SetBytes(x01))
	p.Y.A1.SetBigInt(new(big.Int).SetBytes(x10))
	p.Y.A0.SetBigInt(new(big.Int).SetBytes(x11))
	if !p.IsOnCurve() {
		return p, fmt.Errorf("G2 not on curve")
	}
	return p, nil
}
