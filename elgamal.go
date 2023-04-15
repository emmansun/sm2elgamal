package sm2elgamal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"sync"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm2/sm2ec"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var (
	babySteps          = 1 << 21
	giantSteps         = 1 << 11
	signedGiantSteps   = 1 << 10
	poinCompressionLen = 7
)

var (
	nMinusOne              *big.Int
	giantBaseX, giantBaseY *big.Int
	babyLookupTable        map[string]uint32
	babyLookupTableOnce    sync.Once
)

var ErrOverflow = fmt.Errorf("the value is overflow")

func lookupTable() map[string]uint32 {
	babyLookupTableOnce.Do(func() {
		sm2Curve := sm2.P256()
		nMinusOne = new(big.Int).Sub(sm2.P256().Params().N, big.NewInt(1))
		giantBaseX, giantBaseY = sm2Curve.ScalarBaseMult(new(big.Int).Sub(sm2.P256().Params().N, big.NewInt(int64(babySteps))).Bytes())

		babyLookupTable = make(map[string]uint32)
		bin, err := os.ReadFile("sm2_lookup_table.bin")
		if err != nil {
			panic(err)
		}
		size := len(bin) / poinCompressionLen

		for i := 0; i < size; i++ {
			p := bin[:poinCompressionLen]
			bin = bin[poinCompressionLen:]
			babyLookupTable[string(p)] = uint32(i + 1)
		}
	})
	return babyLookupTable
}

// Ciphertext sturcture represents EL-Gamal ecnryption result.
type Ciphertext struct {
	curve elliptic.Curve
	c1    []byte
	c2    []byte
}

// Add returns c1 + c2.
func (ret *Ciphertext) Add(c1, c2 *Ciphertext) *Ciphertext {
	x11, y11 := sm2ec.UnmarshalCompressed(c1.curve, c1.c1)
	x12, y12 := sm2ec.UnmarshalCompressed(c1.curve, c1.c2)

	x21, y21 := sm2ec.UnmarshalCompressed(c2.curve, c2.c1)
	x22, y22 := sm2ec.UnmarshalCompressed(c2.curve, c2.c2)

	x31, y31 := c1.curve.Add(x11, y11, x21, y21)
	x32, y32 := c1.curve.Add(x12, y12, x22, y22)

	ret.curve = c1.curve
	ret.c1 = elliptic.MarshalCompressed(c1.curve, x31, y31)
	ret.c2 = elliptic.MarshalCompressed(c1.curve, x32, y32)
	return ret
}

// Sum returns cumulative sum value
func (ret *Ciphertext) Sum(values ...*Ciphertext) *Ciphertext {
	v0 := values[0]
	v0c1x, v0c1y := sm2ec.UnmarshalCompressed(v0.curve, v0.c1)
	v0c2x, v0c2y := sm2ec.UnmarshalCompressed(v0.curve, v0.c2)
	for i := 1; i < len(values); i++ {
		vi := values[i]
		vic1x, vic1y := sm2ec.UnmarshalCompressed(vi.curve, vi.c1)
		vic2x, vic2y := sm2ec.UnmarshalCompressed(vi.curve, vi.c2)
		v0c1x, v0c1y = v0.curve.Add(vic1x, vic1y, v0c1x, v0c1y)
		v0c2x, v0c2y = v0.curve.Add(vic2x, vic2y, v0c2x, v0c2y)
	}
	ret.curve = v0.curve
	ret.c1 = elliptic.MarshalCompressed(v0.curve, v0c1x, v0c1y)
	ret.c2 = elliptic.MarshalCompressed(v0.curve, v0c2x, v0c2y)
	return ret
}

// Sub returns c1 - c2.
func (ret *Ciphertext) Sub(c1, c2 *Ciphertext) *Ciphertext {
	x11, y11 := sm2ec.UnmarshalCompressed(c1.curve, c1.c1)
	x12, y12 := sm2ec.UnmarshalCompressed(c1.curve, c1.c2)

	x21, y21 := sm2ec.UnmarshalCompressed(c2.curve, c2.c1)
	x22, y22 := sm2ec.UnmarshalCompressed(c2.curve, c2.c2)

	nMinus1 := new(big.Int).Sub(c1.curve.Params().N, big.NewInt(1)).Bytes()

	x21, y21 = c1.curve.ScalarMult(x21, y21, nMinus1)
	x22, y22 = c1.curve.ScalarMult(x22, y22, nMinus1)

	x31, y31 := c1.curve.Add(x11, y11, x21, y21)
	x32, y32 := c1.curve.Add(x12, y12, x22, y22)

	ret.curve = c1.curve
	ret.c1 = elliptic.MarshalCompressed(c1.curve, x31, y31)
	ret.c2 = elliptic.MarshalCompressed(c1.curve, x32, y32)
	return ret
}

// ScalarMultUint32 scalar mutiples the ciphertext with m.
func (ret *Ciphertext) ScalarMultUint32(c *Ciphertext, m uint32) *Ciphertext {
	if m == 0 {
		panic("can't scalar multiple zero")
	}
	x1, y1 := sm2ec.UnmarshalCompressed(c.curve, c.c1)
	x2, y2 := sm2ec.UnmarshalCompressed(c.curve, c.c2)

	x1, y1 = c.curve.ScalarMult(x1, y1, big.NewInt(int64(m)).Bytes())
	x2, y2 = c.curve.ScalarMult(x2, y2, big.NewInt(int64(m)).Bytes())
	ret.c1 = elliptic.MarshalCompressed(c.curve, x1, y1)
	ret.c2 = elliptic.MarshalCompressed(c.curve, x2, y2)

	ret.curve = c.curve

	return ret
}

// ScalarMultInt32 scalar mutiples the ciphertext with m.
func (ret *Ciphertext) ScalarMultInt32(c *Ciphertext, m int32) *Ciphertext {
	if m == 0 {
		panic("can't scalar multiple zero")
	}
	x1, y1 := sm2ec.UnmarshalCompressed(c.curve, c.c1)
	x2, y2 := sm2ec.UnmarshalCompressed(c.curve, c.c2)
	mValue := getFieldValue(c.curve, m)
	x1, y1 = c.curve.ScalarMult(x1, y1, mValue.Bytes())
	x2, y2 = c.curve.ScalarMult(x2, y2, mValue.Bytes())
	ret.c1 = elliptic.MarshalCompressed(c.curve, x1, y1)
	ret.c2 = elliptic.MarshalCompressed(c.curve, x2, y2)

	ret.curve = c.curve

	return ret
}

// Marshal converts the ciphertext to ASN.1 DER form.
func Marshal(c *Ciphertext) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1OctetString(c.c1)
		b.AddASN1OctetString(c.c2)
	})
	return b.Bytes()
}

// Unmarshal parses ciphertext in ASN.1 DER form.
func Unmarshal(der []byte) (*Ciphertext, error) {
	var (
		ret   *Ciphertext = &Ciphertext{}
		inner cryptobyte.String
	)
	input := cryptobyte.String(der)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Bytes(&ret.c1, asn1.OCTET_STRING) ||
		!inner.ReadASN1Bytes(&ret.c2, asn1.OCTET_STRING) ||
		!inner.Empty() {
		return nil, errors.New("invalid asn1 format ciphertext")
	}
	ret.curve = sm2.P256()
	return ret, nil
}

// randFieldElement returns a random element of the order of the given
// curve using the procedure given in FIPS 186-4, Appendix B.5.2.
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	// See randomPoint for notes on the algorithm. This has to match, or s390x
	// signatures will come out different from other architectures, which will
	// break TLS recorded tests.
	for {
		N := c.Params().N
		b := make([]byte, (N.BitLen()+7)/8)
		if _, err = io.ReadFull(rand, b); err != nil {
			return
		}
		if excess := len(b)*8 - N.BitLen(); excess > 0 {
			b[0] >>= excess
		}
		k = new(big.Int).SetBytes(b)
		if k.Sign() != 0 && k.Cmp(N) < 0 {
			return
		}
	}
}

// EncryptUint32 encrypts m with the publickey.
func EncryptUint32(random io.Reader, pub *ecdsa.PublicKey, m uint32) (*Ciphertext, error) {
	r, err := randFieldElement(pub.Curve, random)
	if err != nil {
		return nil, err
	}
	// c1 = rG
	x1, y1 := pub.Curve.ScalarBaseMult(r.Bytes())
	// c2 = rP
	x11, y11 := pub.Curve.ScalarMult(pub.X, pub.Y, r.Bytes())

	var x2, y2 *big.Int
	if m == 0 {
		x2 = big.NewInt(0)
		y2 = big.NewInt(0)
	} else {
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], m)
		x2, y2 = pub.Curve.ScalarBaseMult(a[:])
	}
	// c2 = rP + mG
	x2, y2 = pub.Curve.Add(x11, y11, x2, y2)

	return &Ciphertext{pub.Curve, elliptic.MarshalCompressed(pub.Curve, x1, y1), elliptic.MarshalCompressed(pub.Curve, x2, y2)}, nil
}

func getFieldValue(curve elliptic.Curve, m int32) *big.Int {
	gVal := big.NewInt(int64(m))
	if m < 0 {
		gVal.Add(gVal, curve.Params().N)
	}
	return gVal
}

// EncryptInt32 encrypts m with the publickey.
func EncryptInt32(random io.Reader, pub *ecdsa.PublicKey, m int32) (*Ciphertext, error) {
	r, err := randFieldElement(pub.Curve, random)
	if err != nil {
		return nil, err
	}
	// c1 = rG
	x1, y1 := pub.Curve.ScalarBaseMult(r.Bytes())
	// c2 = rP
	x11, y11 := pub.Curve.ScalarMult(pub.X, pub.Y, r.Bytes())

	var x2, y2 *big.Int
	if m == 0 {
		x2 = big.NewInt(0)
		y2 = big.NewInt(0)
	} else {
		mVal := getFieldValue(pub.Curve, m)
		x2, y2 = pub.Curve.ScalarBaseMult(mVal.Bytes())
	}
	// c2 = rP + mG = r*dG + mG = d*rG + mG = d*c1 + mG
	// mG = c2 - d*c1
	x2, y2 = pub.Curve.Add(x11, y11, x2, y2)

	return &Ciphertext{pub.Curve, elliptic.MarshalCompressed(pub.Curve, x1, y1), elliptic.MarshalCompressed(pub.Curve, x2, y2)}, nil
}

// PrivateKey is an interface for elgamal decription requirement abstraction
type PrivateKey interface {
	// GetCurve returns this private key's Curve
	GetCurve() elliptic.Curve
	// GetD returns this private key's value
	GetD() *big.Int
}

// sm2PrivateKey is a wrapper struct for [sm2.PrivateKey] to implement [PrivateKey] interface.
type sm2PrivateKey struct {
	sm2.PrivateKey
}

func (priv *sm2PrivateKey) GetCurve() elliptic.Curve {
	return priv.Curve
}

func (priv *sm2PrivateKey) GetD() *big.Int {
	return priv.D
}

// DecryptUint32 decrypts ciphertext to uint32, if the value overflow, it returns ErrOverflow.
func DecryptUint32(priv *sm2.PrivateKey, ciphertext *Ciphertext) (uint32, error) {
	return decryptUint32(&sm2PrivateKey{*priv}, ciphertext)
}

// decryptUint32 decrypts ciphertext to uint32, if the value overflow, it returns ErrOverflow.
func decryptUint32(priv PrivateKey, ciphertext *Ciphertext) (uint32, error) {
	curve := priv.GetCurve()
	x1, y1 := sm2ec.UnmarshalCompressed(curve, ciphertext.c1)
	x2, y2 := sm2ec.UnmarshalCompressed(curve, ciphertext.c2)

	x11, y11 := curve.ScalarMult(x1, y1, new(big.Int).Sub(curve.Params().N, priv.GetD()).Bytes())
	x22, y22 := curve.Add(x2, y2, x11, y11)
	if x22.Sign() == 0 && y22.Sign() == 0 {
		return 0, nil
	}

	c := elliptic.MarshalCompressed(curve, x22, y22)
	value, prs := lookupTable()[string(c[:poinCompressionLen])]
	if prs {
		return value, nil
	}

	for i := 1; i < giantSteps; i++ {
		x22, y22 = curve.Add(x22, y22, giantBaseX, giantBaseY)
		if x22.Sign() == 0 && y22.Sign() == 0 {
			return uint32(i * babySteps), nil
		}
		c = elliptic.MarshalCompressed(curve, x22, y22)
		value, prs = lookupTable()[string(c[:poinCompressionLen])]
		if prs {
			return uint32(i*babySteps) + value, nil
		}
	}
	return 0, ErrOverflow
}

// DecryptInt32 decrypts ciphertext to int32, if the value overflow, it returns ErrOverflow.
// The negative value will be slower than positive value.
func DecryptInt32(priv *sm2.PrivateKey, ciphertext *Ciphertext) (int32, error) {
	return decryptInt32(&sm2PrivateKey{*priv}, ciphertext)
}

// decryptInt32 decrypts ciphertext to int32, if the value overflow, it returns ErrOverflow.
// The negative value will be slower than positive value.
func decryptInt32(priv PrivateKey, ciphertext *Ciphertext) (int32, error) {
	curve := priv.GetCurve()
	x1, y1 := sm2ec.UnmarshalCompressed(curve, ciphertext.c1)
	x2, y2 := sm2ec.UnmarshalCompressed(curve, ciphertext.c2)

	x11, y11 := curve.ScalarMult(x1, y1, new(big.Int).Sub(curve.Params().N, priv.GetD()).Bytes())
	x22, y22 := curve.Add(x2, y2, x11, y11)
	if x22.Sign() == 0 && y22.Sign() == 0 {
		return 0, nil
	}

	ret := decryptSigned(curve, x22, y22)
	if ret != 0 {
		return ret, nil
	}

	xNeg, yNeg := curve.ScalarMult(x22, y22, nMinusOne.Bytes())

	ret = decryptSigned(curve, xNeg, yNeg)
	if ret != 0 {
		return -ret, nil
	}

	return 0, ErrOverflow
}

func decryptSigned(curve elliptic.Curve, x, y *big.Int) int32 {
	c := elliptic.MarshalCompressed(curve, x, y)
	value, prs := lookupTable()[string(c[:poinCompressionLen])]
	if prs {
		return int32(value)
	}
	for i := 1; i < signedGiantSteps; i++ {
		x, y = curve.Add(x, y, giantBaseX, giantBaseY)
		if x.Sign() == 0 && y.Sign() == 0 {
			return int32(i * babySteps)
		}
		c := elliptic.MarshalCompressed(curve, x, y)
		value, prs := lookupTable()[string(c[:poinCompressionLen])]
		if prs {
			return int32(i*babySteps + int(value))
		}
	}
	return 0
}
