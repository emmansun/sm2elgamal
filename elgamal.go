package sm2elgamal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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

type babyElement struct {
	Value []byte
	Index uint32
}

var (
	babySteps        = 1 << 21
	giantSteps       = 1 << 11
	signedGiantSteps = 1 << 10
)

var (
	giantBaseX, giantBaseY *big.Int
	babyLookupTable        map[string]babyElement
	babyLookupTableOnce    sync.Once
)

var ErrOverflow = fmt.Errorf("the value is overflow")

func lookupTable() map[string]babyElement {
	babyLookupTableOnce.Do(func() {
		sm2Curve := sm2.P256()
		giantBaseX, giantBaseY = sm2Curve.ScalarBaseMult(new(big.Int).Sub(sm2.P256().Params().N, big.NewInt(int64(babySteps))).Bytes())

		babyLookupTable = make(map[string]babyElement)
		bin, err := os.ReadFile("sm2_lookup_table.bin")
		if err != nil {
			panic(err)
		}
		size := len(bin) / 33

		for i := 0; i < size; i++ {
			p := bin[i*33 : (i+1)*33]
			babyLookupTable[string(p)] = babyElement{p, uint32(i + 1)}
		}
	})
	return babyLookupTable
}

func LookupTableSize() int {
	return len(lookupTable())
}

type Ciphertext struct {
	curve elliptic.Curve
	c1    []byte
	c2    []byte
}

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

// ScalarMult
func (ret *Ciphertext) ScalarMult(c *Ciphertext, m uint32) *Ciphertext {
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

func (ret *Ciphertext) ScalarMultSigned(c *Ciphertext, m int32) *Ciphertext {
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

func Marshal(c *Ciphertext) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1OctetString(c.c1)
		b.AddASN1OctetString(c.c2)
	})
	return b.Bytes()
}

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

func Encrypt(random io.Reader, pub *ecdsa.PublicKey, m uint32) (*Ciphertext, error) {
	k, err := randFieldElement(pub.Curve, random)
	if err != nil {
		return nil, err
	}
	x1, y1 := pub.Curve.ScalarBaseMult(k.Bytes())
	x11, y11 := pub.Curve.ScalarMult(pub.X, pub.Y, k.Bytes())

	var x2, y2 *big.Int
	if m == 0 {
		x2 = big.NewInt(0)
		y2 = big.NewInt(0)
	} else {
		x2, y2 = pub.Curve.ScalarBaseMult(big.NewInt(int64(m)).Bytes())
	}
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

func EncryptSigned(random io.Reader, pub *ecdsa.PublicKey, m int32) (*Ciphertext, error) {
	k, err := randFieldElement(pub.Curve, random)
	if err != nil {
		return nil, err
	}
	x1, y1 := pub.Curve.ScalarBaseMult(k.Bytes())
	x11, y11 := pub.Curve.ScalarMult(pub.X, pub.Y, k.Bytes())

	var x2, y2 *big.Int
	if m == 0 {
		x2 = big.NewInt(0)
		y2 = big.NewInt(0)
	} else {
		mVal := getFieldValue(pub.Curve, m)
		x2, y2 = pub.Curve.ScalarBaseMult(mVal.Bytes())
	}
	x2, y2 = pub.Curve.Add(x11, y11, x2, y2)

	return &Ciphertext{pub.Curve, elliptic.MarshalCompressed(pub.Curve, x1, y1), elliptic.MarshalCompressed(pub.Curve, x2, y2)}, nil
}

func Decrypt(priv *sm2.PrivateKey, ciphertext *Ciphertext) (uint32, error) {
	x1, y1 := sm2ec.UnmarshalCompressed(priv.Curve, ciphertext.c1)
	x2, y2 := sm2ec.UnmarshalCompressed(priv.Curve, ciphertext.c2)

	x11, y11 := priv.Curve.ScalarMult(x1, y1, new(big.Int).Sub(priv.Params().N, priv.D).Bytes())
	x22, y22 := priv.Curve.Add(x2, y2, x11, y11)
	if x22.Sign() == 0 && y22.Sign() == 0 {
		return 0, nil
	}

	c := elliptic.MarshalCompressed(priv.Curve, x22, y22)
	value, prs := lookupTable()[string(c)]
	if prs {
		return value.Index, nil
	}

	for i := 1; i < giantSteps; i++ {
		x22, y22 = priv.Add(x22, y22, giantBaseX, giantBaseY)
		if x22.Sign() == 0 && y22.Sign() == 0 {
			return uint32(i * babySteps), nil
		}
		c = elliptic.MarshalCompressed(priv.Curve, x22, y22)
		value, prs = lookupTable()[string(c)]
		if prs {
			return uint32(i*babySteps + int(value.Index)), nil
		}
	}
	return 0, ErrOverflow
}

func decryptSigned(priv *sm2.PrivateKey, x, y *big.Int) int32 {
	c := elliptic.MarshalCompressed(priv.Curve, x, y)
	value, prs := lookupTable()[string(c)]
	if prs {
		return int32(value.Index)
	}
	for i := 1; i < signedGiantSteps; i++ {
		x, y = priv.Add(x, y, giantBaseX, giantBaseY)
		if x.Sign() == 0 && y.Sign() == 0 {
			return int32(i * babySteps)
		}
		c := elliptic.MarshalCompressed(priv.Curve, x, y)
		value, prs := lookupTable()[string(c)]
		if prs {
			return int32(i*babySteps + int(value.Index))
		}
	}
	return 0
}

func DecryptSigned(priv *sm2.PrivateKey, ciphertext *Ciphertext) (int32, error) {
	x1, y1 := sm2ec.UnmarshalCompressed(priv.Curve, ciphertext.c1)
	x2, y2 := sm2ec.UnmarshalCompressed(priv.Curve, ciphertext.c2)

	x11, y11 := priv.Curve.ScalarMult(x1, y1, new(big.Int).Sub(priv.Params().N, priv.D).Bytes())
	x22, y22 := priv.Curve.Add(x2, y2, x11, y11)
	if x22.Sign() == 0 && y22.Sign() == 0 {
		return 0, nil
	}

	ret := decryptSigned(priv, x22, y22)
	if ret != 0 {
		return ret, nil
	}

	xNeg, yNeg := priv.Curve.ScalarMult(x22, y22, new(big.Int).Sub(priv.Params().N, big.NewInt(1)).Bytes())

	ret = decryptSigned(priv, xNeg, yNeg)
	if ret != 0 {
		return -ret, nil
	}

	return 0, ErrOverflow
}
