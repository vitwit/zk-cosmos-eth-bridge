package ed25519

import (
	"math/big"

	"github.com/consensys/gnark/std/math/emulated"
)

// Ed25519Fp provides type parametrization for field emulation of Ed25519 base field:
// q = 2^255 - 19
type Ed25519Fp struct{}

func (Ed25519Fp) NbLimbs() uint     { return 4 }
func (Ed25519Fp) BitsPerLimb() uint { return 64 }
func (Ed25519Fp) IsPrime() bool     { return true }
func (Ed25519Fp) Modulus() *big.Int {
	q := new(big.Int).Lsh(big.NewInt(1), 255)
	q.Sub(q, big.NewInt(19))
	return q
}

// Ed25519Fr provides type parametrization for field emulation of Ed25519 scalar field:
// l = 2^252 + 27742317777372353535851937790883648493
type Ed25519Fr struct{}

func (Ed25519Fr) NbLimbs() uint     { return 4 }
func (Ed25519Fr) BitsPerLimb() uint { return 64 }
func (Ed25519Fr) IsPrime() bool     { return true }
func (Ed25519Fr) Modulus() *big.Int {
	l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	return l
}

// Point represents a point on the Twisted Edwards curve Ed25519
type Point struct {
	X, Y emulated.Element[Ed25519Fp]
}

// Ed25519Params holds the curve parameters for Ed25519 in twisted Edwards form:
// ax^2 + y^2 = 1 + dx^2y^2
type Ed25519Params struct {
	A     emulated.Element[Ed25519Fp]
	D     emulated.Element[Ed25519Fp]
	BaseX emulated.Element[Ed25519Fp]
	BaseY emulated.Element[Ed25519Fp]
	Order *big.Int
}

func GetEd25519Params() Ed25519Params {
	// a = -1
	// d = -121665 * inv(121666) mod q
	q := Ed25519Fp{}.Modulus()
	a := big.NewInt(-1)
	a.Mod(a, q)

	d, _ := new(big.Int).SetString("37095705934669439343138083508754565189542113879843219016388785533085940283555", 10)

	bx, _ := new(big.Int).SetString("15112221349535400772501151409588531511454012693041857206046113283949847762202", 10)
	by, _ := new(big.Int).SetString("46316835694926478169428394003475163141307993866256225615783033603165251855960", 10)

	return Ed25519Params{
		A:     emulated.ValueOf[Ed25519Fp](a),
		D:     emulated.ValueOf[Ed25519Fp](d),
		BaseX: emulated.ValueOf[Ed25519Fp](bx),
		BaseY: emulated.ValueOf[Ed25519Fp](by),
		Order: Ed25519Fr{}.Modulus(),
	}
}
