package sm2elgamal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"io"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
)

type TwistedElgamal struct {
	Curve elliptic.Curve
	X, Y  *big.Int // H
}

func NewTwistedElgamal(rand io.Reader) (*TwistedElgamal, error) {
	h, err := randFieldElement(sm2.P256(), rand)
	if err != nil {
		return nil, err
	}
	te := &TwistedElgamal{}
	te.Curve = sm2.P256()
	te.X, te.Y = te.Curve.ScalarBaseMult(h.Bytes())
	return te, nil
}

func FromPrivateKey(priv *sm2.PrivateKey) (*TwistedElgamal) {
	te := &TwistedElgamal{}
	te.Curve = priv.Curve
	te.X, te.Y = priv.ScalarMult(priv.X, priv.Y, priv.D.Bytes())
	return te
}

// A invertible implements fast inverse in GF(N).
type invertible interface {
	// Inverse returns the inverse of k mod Params().N.
	Inverse(k *big.Int) *big.Int
}

// fermatInverse calculates the inverse of k in GF(P) using Fermat's method
// (exponentiation modulo P - 2, per Euler's theorem). This has better
// constant-time properties than Euclid's method (implemented in
// math/big.Int.ModInverse and FIPS 186-4, Appendix C.1) although math/big
// itself isn't strictly constant-time so it's not perfect.
func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
}

func (te *TwistedElgamal) GenerateKey(rand io.Reader) (*sm2.PrivateKey, error) {
	c := sm2.P256()
	d, err := randFieldElement(c, rand)
	if err != nil {
		return nil, err
	}
	priv := new(sm2.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = d

	var dInv *big.Int

	if in, ok := priv.Curve.(invertible); ok {
		dInv = in.Inverse(d)
	} else {
		dInv = fermatInverse(d, c.Params().N)
	}

	// P = s^(-1) * H
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarMult(te.X, te.Y, dInv.Bytes())

	return priv, nil
}

// EncryptUint32 encrypts m with the publickey.
func (te *TwistedElgamal) EncryptUint32(random io.Reader, pub *ecdsa.PublicKey, m uint32) (*Ciphertext, error) {
	k, err := randFieldElement(pub.Curve, random)
	if err != nil {
		return nil, err
	}
	// D = rP
	x1, y1 := pub.Curve.ScalarMult(pub.X, pub.Y, k.Bytes())
	// C = rH
	x11, y11 := pub.Curve.ScalarMult(te.X, te.Y, k.Bytes())

	var x2, y2 *big.Int
	if m == 0 {
		x2 = big.NewInt(0)
		y2 = big.NewInt(0)
	} else {
		x2, y2 = pub.Curve.ScalarBaseMult(big.NewInt(int64(m)).Bytes())
	}
	// C = rH + mG
	x2, y2 = pub.Curve.Add(x11, y11, x2, y2)

	return &Ciphertext{pub.Curve, elliptic.MarshalCompressed(pub.Curve, x1, y1), elliptic.MarshalCompressed(pub.Curve, x2, y2)}, nil
}

// EncryptInt32 encrypts m with the publickey.
func (te *TwistedElgamal) EncryptInt32(random io.Reader, pub *ecdsa.PublicKey, m int32) (*Ciphertext, error) {
	k, err := randFieldElement(pub.Curve, random)
	if err != nil {
		return nil, err
	}
	// D = rP
	x1, y1 := pub.Curve.ScalarMult(pub.X, pub.Y, k.Bytes())
	// C = rH
	x11, y11 := pub.Curve.ScalarMult(te.X, te.Y, k.Bytes())

	var x2, y2 *big.Int
	if m == 0 {
		x2 = big.NewInt(0)
		y2 = big.NewInt(0)
	} else {
		mVal := getFieldValue(pub.Curve, m)
		x2, y2 = pub.Curve.ScalarBaseMult(mVal.Bytes())
	}
	// C = rH + mG
	x2, y2 = pub.Curve.Add(x11, y11, x2, y2)

	return &Ciphertext{pub.Curve, elliptic.MarshalCompressed(pub.Curve, x1, y1), elliptic.MarshalCompressed(pub.Curve, x2, y2)}, nil
}
