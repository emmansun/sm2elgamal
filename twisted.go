package sm2elgamal

// Further references:
//   The Twisted ElGamal Encryption
//     https://spl.solana.com/assets/files/twisted_elgamal-2115c6b1e6c62a2bb4516891b8ae9ee0.pdf
//

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	"io"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
)

// TwistedElgamal is a struct for Twisted Elagaml context which contains H and curve information.
type TwistedElgamal struct {
	Curve elliptic.Curve
	X, Y  *big.Int // H
}

// TwistedPrivateKey is a struct for Twisted private key, its public key can't be derived from D value without H.
type TwistedPrivateKey struct {
	ecdsa.PrivateKey
}

func (priv *TwistedPrivateKey) GetCurve() elliptic.Curve {
	return priv.Curve
}

func (priv *TwistedPrivateKey) GetD() *big.Int {
	return priv.D
}

func (priv *TwistedPrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*TwistedPrivateKey)
	if !ok {
		return false
	}
	return priv.PublicKey.Equal(&xx.PublicKey) && bigIntEqual(priv.D, xx.D)
}

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
	return subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
}

// NewTwistedElgamal creates one SM2 Twisted Elgamal context.
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

// FromPrivateKey creates related SM2 Twisted Elgamal context.
func FromPrivateKey(priv *TwistedPrivateKey) *TwistedElgamal {
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

// GenerateKey generates a public and private key pair.
func (te *TwistedElgamal) GenerateKey(rand io.Reader) (*TwistedPrivateKey, error) {
	c := sm2.P256()
	d, err := randFieldElement(c, rand)
	if err != nil {
		return nil, err
	}
	priv := new(TwistedPrivateKey)
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
	r, err := randFieldElement(pub.Curve, random)
	if err != nil {
		return nil, err
	}
	// D = rP
	x1, y1 := pub.Curve.ScalarMult(pub.X, pub.Y, r.Bytes())
	// C = rH
	x11, y11 := pub.Curve.ScalarMult(te.X, te.Y, r.Bytes())

	var x2, y2 *big.Int
	if m == 0 {
		x2 = big.NewInt(0)
		y2 = big.NewInt(0)
	} else {
		x2, y2 = pub.Curve.ScalarBaseMult(big.NewInt(int64(m)).Bytes())
	}
	// C = rH + mG = r*d*(d^(-1)H) + mG = r*dP + mG = d*rP + mG = dD + mG
	// mG = C - dD
	x2, y2 = pub.Curve.Add(x11, y11, x2, y2)

	return &Ciphertext{pub.Curve, elliptic.MarshalCompressed(pub.Curve, x1, y1), elliptic.MarshalCompressed(pub.Curve, x2, y2)}, nil
}

// EncryptInt32 encrypts m with the publickey.
func (te *TwistedElgamal) EncryptInt32(random io.Reader, pub *ecdsa.PublicKey, m int32) (*Ciphertext, error) {
	r, err := randFieldElement(pub.Curve, random)
	if err != nil {
		return nil, err
	}
	// D = rP
	x1, y1 := pub.Curve.ScalarMult(pub.X, pub.Y, r.Bytes())
	// C = rH
	x11, y11 := pub.Curve.ScalarMult(te.X, te.Y, r.Bytes())

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

// EncryptInt32 encrypts m with the publickey.
func (priv *TwistedPrivateKey) EncryptUint32(random io.Reader, m uint32) (*Ciphertext, error) {
	return FromPrivateKey(priv).EncryptUint32(random, &priv.PublicKey, m)
}

// EncryptInt32 encrypts m with the publickey.
func (priv *TwistedPrivateKey) EncryptInt32(random io.Reader, m int32) (*Ciphertext, error) {
	return FromPrivateKey(priv).EncryptInt32(random, &priv.PublicKey, m)
}

// DecryptUint32 decrypts ciphertext to uint32, if the value overflow, it returns ErrOverflow.
func (priv *TwistedPrivateKey) DecryptUint32(ciphertext *Ciphertext) (uint32, error) {
	return decryptUint32(priv, ciphertext)
}

// DecryptInt32 decrypts ciphertext to int32, if the value overflow, it returns ErrOverflow.
// The negative value will be slower than positive value.
func (priv *TwistedPrivateKey) DecryptInt32(ciphertext *Ciphertext) (int32, error) {
	return decryptInt32(priv, ciphertext)
}
