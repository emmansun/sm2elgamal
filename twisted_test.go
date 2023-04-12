package sm2elgamal

import (
	"crypto/rand"
	"testing"
)

var te *TwistedElgamal
var priv *TwistedPrivateKey

func init() {
	te, _ = NewTwistedElgamal(rand.Reader)
	priv, _ = te.GenerateKey(rand.Reader)
}

func testTwistedEncryptDecryptUint32(t *testing.T, priv *TwistedPrivateKey, m uint32) {
	ciphertext, err := priv.EncryptUint32(rand.Reader, m)
	if err != nil {
		t.Fatal(err)
	}
	v, err := priv.DecryptUint32(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if v != m {
		t.Fatalf("expected %x, got %x", m, v)
	}
}

func TestTwistedEncryptDecryptUint32(t *testing.T) {
	for i := 0; i < 10; i++ {
		testTwistedEncryptDecryptUint32(t, priv, uint32(i))
	}
	for i := 0xffffffff; i > 0xfffffff0; i-- {
		testTwistedEncryptDecryptUint32(t, priv, uint32(i))
	}

	for i := 1; i < 10; i++ {
		testTwistedEncryptDecryptUint32(t, priv, uint32(i*babySteps))
	}
}

func testTwistedEncryptDecryptInt32(t *testing.T, priv *TwistedPrivateKey, m int32) {
	ciphertext, err := priv.EncryptInt32(rand.Reader, m)
	if err != nil {
		t.Fatal(err)
	}
	v, err := priv.DecryptInt32(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if v != m {
		t.Fatalf("expected %x, got %x", m, v)
	}
}

func TestTwistedEncryptDecryptInt32(t *testing.T) {
	for i := 0; i < 10; i++ {
		testTwistedEncryptDecryptInt32(t, priv, int32(i))
	}

	for i := -10; i < 0; i++ {
		testTwistedEncryptDecryptInt32(t, priv, int32(i))
	}

	testTwistedEncryptDecryptInt32(t, priv, 0x7fffffff)
	testTwistedEncryptDecryptInt32(t, priv, -0x7fffffff)

	for i := 1; i < 10; i++ {
		testTwistedEncryptDecryptInt32(t, priv, int32(i*babySteps))
		testTwistedEncryptDecryptInt32(t, priv, int32(-i*babySteps))
	}
}
