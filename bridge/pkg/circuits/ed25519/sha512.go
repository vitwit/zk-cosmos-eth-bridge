package ed25519

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// SHA512 implemented in Gnark
type SHA512 struct {
	api frontend.API
}

func NewSHA512(api frontend.API) *SHA512 {
	return &SHA512{api: api}
}

// K round constants for SHA-512
var K = [80]uint64{
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf345b8ae, 0x59f111f1b604116f, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
}

func (h *SHA512) Sum(msg []uints.U8) []uints.U8 {
	u8Api, _ := uints.NewBytes(h.api)
	padded := h.pad(msg)

	h0 := uint64(0x6a09e667f3bcc908)
	h1 := uint64(0xbb67ae8584caa73b)
	h2 := uint64(0x3c6ef372fe94f82b)
	h3 := uint64(0xa54ff53a5f1d36f1)
	h4 := uint64(0x510e527fade682d1)
	h5 := uint64(0x9b05688c2b3e6c1f)
	h6 := uint64(0x1f83d9abfb41bd6b)
	h7 := uint64(0x5be0cd19137e2179)

	state := [8]frontend.Variable{
		frontend.Variable(h0), frontend.Variable(h1), frontend.Variable(h2), frontend.Variable(h3),
		frontend.Variable(h4), frontend.Variable(h5), frontend.Variable(h6), frontend.Variable(h7),
	}

	for i := 0; i < len(padded); i += 128 {
		block := padded[i : i+128]
		h.compress(u8Api, &state, block)
	}

	var res []uints.U8
	for i := 0; i < 8; i++ {
		bits := h.api.ToBinary(state[i], 64)
		for j := 7; j >= 0; j-- {
			start := j * 8
			val := h.api.FromBinary(bits[start : start+8]...)
			res = append(res, uints.U8{Val: val})
		}
	}
	return res
}

func (h *SHA512) pad(msg []uints.U8) []uints.U8 {
	padded := make([]uints.U8, len(msg))
	copy(padded, msg)
	padded = append(padded, uints.U8{Val: 0x80})

	// Pad with zeros until length is 112 bytes mod 128
	for (len(padded) % 128) != 112 {
		padded = append(padded, uints.U8{Val: 0})
	}

	// Append length in bits (128-bit big-endian)
	msgLenBits := uint64(len(msg)) * 8
	lenBytes := make([]byte, 16)
	for i := 0; i < 8; i++ {
		lenBytes[15-i] = byte(msgLenBits >> (8 * i))
	}
	for i := 0; i < 16; i++ {
		padded = append(padded, uints.U8{Val: frontend.Variable(lenBytes[i])})
	}

	return padded
}

func (h *SHA512) compress(u8Api *uints.Bytes, state *[8]frontend.Variable, block []uints.U8) {
	var w [80]frontend.Variable

	// First 16 words from block
	for i := 0; i < 16; i++ {
		val := frontend.Variable(0)
		for j := 0; j < 8; j++ {
			val = h.api.Add(val, h.api.Mul(block[i*8+j].Val, 1<<(8*(7-j))))
		}
		w[i] = val
	}

	// Extend to 80 words
	for i := 16; i < 80; i++ {
		s0 := h.sigma0(w[i-15])
		s1 := h.sigma1(w[i-2])

		// w[i] = s1 + w[i-7] + s0 + w[i-16]
		sum := h.api.Add(s1, w[i-7], s0, w[i-16])
		w[i] = h.reduce64(sum)
	}

	a, b, c, d, e, f, g, hh := state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]

	for i := 0; i < 80; i++ {
		S1 := h.Sigma1(e)
		ch := h.Ch(e, f, g)
		temp1 := h.api.Add(hh, S1, ch, frontend.Variable(K[i]), w[i])
		temp1 = h.reduce64(temp1)

		S0 := h.Sigma0(a)
		maj := h.Maj(a, b, c)
		temp2 := h.api.Add(S0, maj)
		temp2 = h.reduce64(temp2)

		hh = g
		g = f
		f = e
		e = h.reduce64(h.api.Add(d, temp1))
		d = c
		c = b
		b = a
		a = h.reduce64(h.api.Add(temp1, temp2))
	}

	state[0] = h.reduce64(h.api.Add(state[0], a))
	state[1] = h.reduce64(h.api.Add(state[1], b))
	state[2] = h.reduce64(h.api.Add(state[2], c))
	state[3] = h.reduce64(h.api.Add(state[3], d))
	state[4] = h.reduce64(h.api.Add(state[4], e))
	state[5] = h.reduce64(h.api.Add(state[5], f))
	state[6] = h.reduce64(h.api.Add(state[6], g))
	state[7] = h.reduce64(h.api.Add(state[7], hh))
}

func (h *SHA512) reduce64(v frontend.Variable) frontend.Variable {
	bits := h.api.ToBinary(v, 128) // Enough bits to handle addition overflows
	return h.api.FromBinary(bits[:64]...)
}

func (h *SHA512) Ch(x, y, z frontend.Variable) frontend.Variable {
	// (x & y) ^ (~x & z)
	bx := h.api.ToBinary(x, 64)
	by := h.api.ToBinary(y, 64)
	bz := h.api.ToBinary(z, 64)

	res := make([]frontend.Variable, 64)
	for i := 0; i < 64; i++ {
		// bx[i]*by[i] + (1-bx[i])*bz[i]
		res[i] = h.api.Add(h.api.Mul(bx[i], by[i]), h.api.Mul(h.api.Sub(1, bx[i]), bz[i]))
	}
	return h.api.FromBinary(res...)
}

func (h *SHA512) Maj(x, y, z frontend.Variable) frontend.Variable {
	// (x & y) ^ (x & z) ^ (y & z)
	bx := h.api.ToBinary(x, 64)
	by := h.api.ToBinary(y, 64)
	bz := h.api.ToBinary(z, 64)

	res := make([]frontend.Variable, 64)
	for i := 0; i < 64; i++ {
		// x&y + x&z + y&z - 2*x*y*z ?
		// Maj(a,b,c) = (a+b+c > 1)
		sum := h.api.Add(bx[i], by[i], bz[i])
		sumBits := h.api.ToBinary(sum, 2)
		res[i] = h.api.Lookup2(sumBits[0], sumBits[1], frontend.Variable(0), frontend.Variable(0), frontend.Variable(1), frontend.Variable(1))
	}
	return h.api.FromBinary(res...)
}

func (h *SHA512) Sigma0(x frontend.Variable) frontend.Variable {
	return h.xor(h.rotr(x, 28), h.rotr(x, 34), h.rotr(x, 39))
}

func (h *SHA512) Sigma1(x frontend.Variable) frontend.Variable {
	return h.xor(h.rotr(x, 14), h.rotr(x, 18), h.rotr(x, 41))
}

func (h *SHA512) sigma0(x frontend.Variable) frontend.Variable {
	return h.xor(h.rotr(x, 1), h.rotr(x, 8), h.shr(x, 7))
}

func (h *SHA512) sigma1(x frontend.Variable) frontend.Variable {
	return h.xor(h.rotr(x, 19), h.rotr(x, 61), h.shr(x, 6))
}

func (h *SHA512) rotr(x frontend.Variable, n int) frontend.Variable {
	bits := h.api.ToBinary(x, 64)
	res := make([]frontend.Variable, 64)
	for i := 0; i < 64; i++ {
		res[i] = bits[(i+n)%64]
	}
	return h.api.FromBinary(res...)
}

func (h *SHA512) shr(x frontend.Variable, n int) frontend.Variable {
	bits := h.api.ToBinary(x, 64)
	res := make([]frontend.Variable, 64)
	for i := 0; i < 64-n; i++ {
		res[i] = bits[i+n]
	}
	for i := 64 - n; i < 64; i++ {
		res[i] = 0
	}
	return h.api.FromBinary(res...)
}

func (h *SHA512) xor(vars ...frontend.Variable) frontend.Variable {
	bits := make([][]frontend.Variable, len(vars))
	for i := 0; i < len(vars); i++ {
		bits[i] = h.api.ToBinary(vars[i], 64)
	}

	res := make([]frontend.Variable, 64)
	for i := 0; i < 64; i++ {
		xorVal := bits[0][i]
		for j := 1; j < len(vars); j++ {
			xorVal = h.api.Xor(xorVal, bits[j][i])
		}
		res[i] = xorVal
	}
	return h.api.FromBinary(res...)
}
