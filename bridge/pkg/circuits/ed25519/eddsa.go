package ed25519

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

type Signature struct {
	R Point
	S emulated.Element[Ed25519Fr]
}

type PublicKey struct {
	A Point
}

type EdDSA struct {
	api   frontend.API
	curve *Curve
}

func NewEdDSA(api frontend.API) (*EdDSA, error) {
	curve, err := NewCurve(api)
	if err != nil {
		return nil, err
	}
	return &EdDSA{
		api:   api,
		curve: curve,
	}, nil
}

func (e *EdDSA) Verify(sig Signature, msg []uints.U8, pubKey PublicKey, enabled frontend.Variable) error {
	// 1. Compute k = SHA512(R || A || M) mod L
	kBits := e.computeChallenge(sig.R, pubKey.A, msg)

	// 2. Compute lhs = [S]B
	fr, err := emulated.NewField[Ed25519Fr](e.api)
	if err != nil {
		return err
	}
	// Reduce S just in case, then convert to bits for ScalarMul
	sBits := fr.ToBits(fr.Reduce(&sig.S))

	// Base point B
	basePoint := Point{
		X: e.curve.params.BaseX,
		Y: e.curve.params.BaseY,
	}
	lhs := e.curve.ScalarMul(basePoint, sBits)

	// 3. Compute rhs = R + [k]A
	kA := e.curve.ScalarMul(pubKey.A, kBits)
	rhs := e.curve.Add(sig.R, kA)

	// 4. Conditional check: if enabled == 1, then [S]B = R + [k]A
	// We use Select on coordinates and then assert equality.
	targetX := e.curve.field.Select(enabled, &rhs.X, &lhs.X)
	targetY := e.curve.field.Select(enabled, &rhs.Y, &lhs.Y)

	e.curve.field.AssertIsEqual(&lhs.X, targetX)
	e.curve.field.AssertIsEqual(&lhs.Y, targetY)

	return nil
}

func (e *EdDSA) computeChallenge(R, A Point, msg []uints.U8) []frontend.Variable {
	sha := NewSHA512(e.api)

	// Serialize R and A
	rBytes := e.SerializePoint(R)
	aBytes := e.SerializePoint(A)

	var data []uints.U8
	data = append(data, rBytes[:]...)
	data = append(data, aBytes[:]...)
	data = append(data, msg...)

	hash := sha.Sum(data) // 64 bytes

	// Reduce 512-bit hash mod L using 4-chunk reduction
	// L = 2^252 + 27742317777372353535851937790883648493
	return e.reduceSHA512(hash)
}

func (e *EdDSA) reduceSHA512(hash []uints.U8) []frontend.Variable {
	fr, _ := emulated.NewField[Ed25519Fr](e.api)

	// Convert 64 bytes to 4 x 128-bit chunks
	// Ed25519 hashes are Little Endian in challenge calculation?
	// RFC 8032: "h = SHA-512(dom2(F, C) || R || A || PH(M))"
	// The hash is treated as a little-endian integer.

	chunks := make([]*emulated.Element[Ed25519Fr], 4)
	for i := 0; i < 4; i++ {
		low := frontend.Variable(0)
		for j := 0; j < 8; j++ {
			low = e.api.Add(low, e.api.Mul(hash[i*16+j].Val, big.NewInt(1).Lsh(big.NewInt(1), uint(8*j))))
		}
		high := frontend.Variable(0)
		for j := 0; j < 8; j++ {
			high = e.api.Add(high, e.api.Mul(hash[i*16+8+j].Val, big.NewInt(1).Lsh(big.NewInt(1), uint(8*j))))
		}
		// Packing into 4 limbs of 64 bits each (low, high, 0, 0)
		chunks[i] = fr.NewElement([]frontend.Variable{low, high, 0, 0})
	}

	// Modular reduction of 512-bit challenge hash mod L
	p128, _ := new(big.Int).SetString("100000000000000000000000000000000", 16)
	p256, _ := new(big.Int).SetString("ffffffffffffffffffffffffffffffec6ef5bf4737dcf70d6ec31748d98951d", 16)
	p384, _ := new(big.Int).SetString("2106215d086329a7ed9ce5a30a2c131b64a7f435e4fdd9539822129a02a6271", 16)

	// k = c0 + c1*2^128 + c2*2^256 + c3*2^384 mod L
	term1 := fr.Mul(chunks[1], fr.NewElement(p128))
	term2 := fr.Mul(chunks[2], fr.NewElement(p256))
	term3 := fr.Mul(chunks[3], fr.NewElement(p384))

	k := fr.Add(chunks[0], term1)
	k = fr.Add(k, term2)
	k = fr.Add(k, term3)
	return fr.ToBits(k)
}

func (e *EdDSA) SerializePoint(p Point) [32]uints.U8 {
	// Standard Ed25519 compression:
	// 32-byte array. First 31 bytes are little-endian Y.
	// Last byte is Y[31] with X[0] (sign bit) in the most significant bit.

	// Get bits of Y (255 bits field)
	yBits := e.curve.field.ToBits(&p.Y) // Little Endian
	xBits := e.curve.field.ToBits(&p.X)

	var res [32]uints.U8

	// Pack Y into 32 bytes (Little Endian)
	for i := 0; i < 31; i++ {
		val := frontend.Variable(0)
		for j := 0; j < 8; j++ {
			val = e.api.Add(val, e.api.Mul(yBits[i*8+j], 1<<j))
		}
		res[i] = uints.U8{Val: val}
	}

	// Last byte: Y[248:255] + X[0] at bit 7
	lastByteVal := frontend.Variable(0)
	for j := 0; j < 7; j++ {
		lastByteVal = e.api.Add(lastByteVal, e.api.Mul(yBits[31*8+j], 1<<j))
	}
	lastByteVal = e.api.Add(lastByteVal, e.api.Mul(xBits[0], 1<<7))
	res[31] = uints.U8{Val: lastByteVal}

	return res
}
