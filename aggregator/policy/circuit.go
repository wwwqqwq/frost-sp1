package policy

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	bn254groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

const ProofOutputsLen = 128

var (
	risc0TagOutput  = sha256.Sum256([]byte("risc0.Output"))
	risc0TagClaim   = sha256.Sum256([]byte("risc0.ReceiptClaim"))
	risc0PostDigest = risc0PostStateDigest()
)

func risc0PostStateDigest() [32]byte {
	tag := sha256.Sum256([]byte("risc0.SystemState"))
	data := append([]byte{}, tag[:]...)
	data = append(data, make([]byte, 32)...)
	data = binary.LittleEndian.AppendUint32(data, 0)
	data = binary.LittleEndian.AppendUint16(data, 1)
	return sha256.Sum256(data)
}

type (
	scalarField    = sw_bn254.ScalarField
	g1Affine       = sw_bn254.G1Affine
	g2Affine       = sw_bn254.G2Affine
	gtEl           = sw_bn254.GTEl
	recurseProof   = stdgroth16.Proof[g1Affine, g2Affine]
	recurseVK      = stdgroth16.VerifyingKey[g1Affine, g2Affine, gtEl]
	recurseWitness = stdgroth16.Witness[scalarField]
)

type frostSlotConfig struct {
	binding   BindingKind
	vk        recurseVK `gnark:"-"`
	pins      map[int]*big.Int
	preDigest [32]byte
}

type frostSlotWitness struct {
	Proof  recurseProof
	Inputs recurseWitness
}

type frostCircuit struct {
	Threshold    int                                `gnark:"-"`
	SlotConfigs  []frostSlotConfig                  `gnark:"-"`
	FrostOutputs [ProofOutputsLen]frontend.Variable `gnark:",public"`
	Slots        []frostSlotWitness
}

var (
	innerStubCCSOnce sync.Once
	innerStubCCS     constraint.ConstraintSystem
	innerStubCCSErr  error
)

func innerStubConstraintSystem() (constraint.ConstraintSystem, error) {
	innerStubCCSOnce.Do(func() {
		innerStubCCS, innerStubCCSErr = frontend.Compile(
			ecc.BN254.ScalarField(), r1cs.NewBuilder, &innerStub{},
		)
	})
	return innerStubCCS, innerStubCCSErr
}

func (c *frostCircuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[scalarField, g1Affine, g2Affine, gtEl](api)
	if err != nil {
		return err
	}
	scalarAPI, err := emulated.NewField[scalarField](api)
	if err != nil {
		return err
	}
	bapi, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	frostU8 := make([]uints.U8, ProofOutputsLen)
	for i, v := range c.FrostOutputs {
		frostU8[i] = bapi.ValueOf(v)
	}

	flags := make([]frontend.Variable, len(c.Slots))
	for i, slot := range c.Slots {
		if err := applyBinding(api, scalarAPI, bapi, c.SlotConfigs[i], slot, frostU8); err != nil {
			return fmt.Errorf("slot %d: %w", i, err)
		}
		ok, err := verifier.IsValidProof(c.SlotConfigs[i].vk, slot.Proof, slot.Inputs, stdgroth16.WithSubgroupCheck())
		if err != nil {
			return fmt.Errorf("slot %d: %w", i, err)
		}
		flags[i] = ok
	}
	enforceThreshold(api, flags, c.Threshold)
	return nil
}

func applyBinding(
	api frontend.API,
	scalarAPI *emulated.Field[scalarField],
	bapi *uints.Bytes,
	cfg frostSlotConfig,
	slot frostSlotWitness,
	frostU8 []uints.U8,
) error {
	for index, value := range cfg.pins {
		scalarAPI.AssertIsEqual(&slot.Inputs.Public[index], scalarAPI.NewElement(value))
	}
	switch cfg.binding {
	case BindingNone:
		return nil
	case BindingSP1Digest:
		expected, err := sp1Digest(api, bapi, scalarAPI, frostU8)
		if err != nil {
			return err
		}
		scalarAPI.AssertIsEqual(&slot.Inputs.Public[1], expected)
	case BindingPinPublic:
		digest, err := risc0ClaimDigest(api, frostU8, cfg.preDigest)
		if err != nil {
			return err
		}
		c0, c1 := risc0ClaimHalves(api, scalarAPI, bapi, digest)
		scalarAPI.AssertIsEqual(&slot.Inputs.Public[2], c0)
		scalarAPI.AssertIsEqual(&slot.Inputs.Public[3], c1)
	default:
		return fmt.Errorf("unknown binding %d", cfg.binding)
	}
	return nil
}

func sha256U8(api frontend.API, parts ...[]uints.U8) ([]uints.U8, error) {
	hasher, err := sha2.New(api)
	if err != nil {
		return nil, err
	}
	for _, part := range parts {
		hasher.Write(part)
	}
	return hasher.Sum(), nil
}

func risc0ClaimDigest(api frontend.API, frostU8 []uints.U8, preDigest [32]byte) ([]uints.U8, error) {
	u8 := uints.NewU8Array
	zero := u8(make([]byte, 32))
	journalDigest, err := sha256U8(api, frostU8)
	if err != nil {
		return nil, err
	}
	outputDigest, err := sha256U8(api,
		u8(risc0TagOutput[:]),
		journalDigest,
		zero,
		u8([]byte{2, 0}),
	)
	if err != nil {
		return nil, err
	}
	return sha256U8(api,
		u8(risc0TagClaim[:]),
		zero,
		u8(preDigest[:]),
		u8(risc0PostDigest[:]),
		outputDigest,
		zero[:8],
		u8([]byte{4, 0}),
	)
}

func risc0ClaimHalves(api frontend.API, scalarAPI *emulated.Field[scalarField], bapi *uints.Bytes, digest []uints.U8) (*emulated.Element[scalarField], *emulated.Element[scalarField]) {
	half := func(start, end int) *emulated.Element[scalarField] {
		var bits []frontend.Variable
		for i := start; i < end; i++ {
			bits = append(bits, api.ToBinary(bapi.Value(digest[i]), 8)...)
		}
		return scalarAPI.FromBits(bits...)
	}
	return half(0, 16), half(16, 32)
}

func enforceThreshold(api frontend.API, flags []frontend.Variable, threshold int) {
	sum := frontend.Variable(0)
	for _, f := range flags {
		sum = api.Add(sum, f)
	}
	prod := frontend.Variable(1)
	for k := threshold; k <= len(flags); k++ {
		prod = api.Mul(prod, api.Sub(sum, k))
	}
	api.AssertIsEqual(prod, 0)
}

func sp1Digest(api frontend.API, bapi *uints.Bytes, scalarAPI *emulated.Field[scalarField], data []uints.U8) (*emulated.Element[scalarField], error) {
	hasher, err := sha2.New(api)
	if err != nil {
		return nil, err
	}
	hasher.Write(data)
	digest := hasher.Sum()
	digest[0] = bapi.And(digest[0], bapi.ValueOf(0x1F))
	var bits []frontend.Variable
	for i := len(digest) - 1; i >= 0; i-- {
		bits = append(bits, api.ToBinary(bapi.Value(digest[i]), 8)...)
	}
	return scalarAPI.FromBits(bits...), nil
}

type innerStub struct {
	V0, V1, V2, V3, V4 frontend.Variable `gnark:",public"`
}

func (innerStub) Define(api frontend.API) error { return nil }

func frostVars(frost []byte) [ProofOutputsLen]frontend.Variable {
	var outs [ProofOutputsLen]frontend.Variable
	for i, b := range frost {
		outs[i] = int(b)
	}
	return outs
}

func buildFrostCircuit(pol Policy, loaded map[BackendID]*Loaded, withWitness bool) (*frostCircuit, error) {
	innerCCS, err := innerStubConstraintSystem()
	if err != nil {
		return nil, err
	}

	c := &frostCircuit{
		Threshold:   pol.Threshold,
		SlotConfigs: make([]frostSlotConfig, len(pol.Slots)),
		Slots:       make([]frostSlotWitness, len(pol.Slots)),
	}
	for i, spec := range pol.Slots {
		l := loaded[spec.Backend]
		if l == nil {
			return nil, fmt.Errorf("slot %d: backend %q not loaded", i, spec.Backend)
		}
		vk, err := stdgroth16.ValueOfVerifyingKeyFixed[g1Affine, g2Affine, gtEl](l.Proof.vk)
		if err != nil {
			return nil, err
		}
		cfg := frostSlotConfig{binding: spec.Binding, vk: vk}
		switch spec.Binding {
		case BindingSP1Digest:
			cfg.pins = map[int]*big.Int{0: frToBig(l.publicInputs[0])}
		case BindingPinPublic:
			cfg.pins = map[int]*big.Int{
				0: frToBig(l.publicInputs[0]),
				1: frToBig(l.publicInputs[1]),
				4: frToBig(l.publicInputs[4]),
			}
			cfg.preDigest = l.preDigest
		}
		c.SlotConfigs[i] = cfg
	}
	if !withWitness {
		for i := range c.Slots {
			c.Slots[i].Inputs = stdgroth16.PlaceholderWitness[scalarField](innerCCS)
			c.Slots[i].Proof = stdgroth16.PlaceholderProof[g1Affine, g2Affine](innerCCS)
		}
		return c, nil
	}

	c.FrostOutputs = frostVars(loaded[BackendSP1].Proof.publicValues)

	for i, spec := range pol.Slots {
		if spec.Binding == BindingNone {
			_, _, g1, g2 := curve.Generators()
			p, err := stdgroth16.ValueOfProof[g1Affine, g2Affine](&bn254groth16.Proof{Ar: g1, Bs: g2, Krs: g1})
			if err != nil {
				return nil, err
			}
			c.Slots[i] = frostSlotWitness{
				Proof:  p,
				Inputs: stdgroth16.PlaceholderWitness[scalarField](innerCCS),
			}
			continue
		}
		l := loaded[spec.Backend]
		p, err := stdgroth16.ValueOfProof[g1Affine, g2Affine](l.Proof.proof)
		if err != nil {
			return nil, err
		}
		w, err := stdgroth16.ValueOfWitness[scalarField](l.Proof.publicWitness)
		if err != nil {
			return nil, err
		}
		c.Slots[i] = frostSlotWitness{Proof: p, Inputs: w}
	}
	return c, nil
}
