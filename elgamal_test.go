package sm2elgamal

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/emmansun/gmsm/sm2"
)

func testEncryptDecryptUint32(t *testing.T, priv *sm2.PrivateKey, m uint32) {
	ciphertext, err := EncryptUint32(rand.Reader, &priv.PublicKey, m)
	if err != nil {
		t.Fatal(err)
	}
	v, err := DecryptUint32(priv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if v != m {
		t.Fatalf("expected %x, got %x", m, v)
	}
}

func TestEncryptDecryptUint32(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	for i := 0; i < 10; i++ {
		testEncryptDecryptUint32(t, priv, uint32(i))
	}
	for i := 0xffffffff; i > 0xfffffff0; i-- {
		testEncryptDecryptUint32(t, priv, uint32(i))
	}

	for i := 1; i < 10; i++ {
		testEncryptDecryptUint32(t, priv, uint32(i*babySteps))
	}
}

func testEncryptDecryptInt32(t *testing.T, priv *sm2.PrivateKey, m int32) {
	ciphertext, err := EncryptInt32(rand.Reader, &priv.PublicKey, m)
	if err != nil {
		t.Fatal(err)
	}
	v, err := DecryptInt32(priv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if v != m {
		t.Fatalf("expected %x, got %x", m, v)
	}
}

func TestEncryptDecryptInt32(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	for i := 0; i < 10; i++ {
		testEncryptDecryptInt32(t, priv, int32(i))
	}

	for i := -10; i < 0; i++ {
		testEncryptDecryptInt32(t, priv, int32(i))
	}

	testEncryptDecryptInt32(t, priv, 0x7fffffff)
	testEncryptDecryptInt32(t, priv, -0x7fffffff)

	for i := 1; i < 10; i++ {
		testEncryptDecryptInt32(t, priv, int32(i*babySteps))
		testEncryptDecryptInt32(t, priv, int32(-i*babySteps))
	}
}

func testAddUint32(t *testing.T, priv *sm2.PrivateKey, m1, m2 uint32) {
	ciphertext1, err := EncryptUint32(rand.Reader, &priv.PublicKey, m1)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext2, err := EncryptUint32(rand.Reader, &priv.PublicKey, m2)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.Add(ciphertext1, ciphertext2)
	v, err := DecryptUint32(priv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if v != m1+m2 {
		t.Fatalf("expected %x, got %x", m1+m2, v)
	}
}

func TestAddUint32(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	testAddUint32(t, priv, 0, 0)
	testAddUint32(t, priv, 0, 2)
	testAddUint32(t, priv, 1, 2)
	testAddUint32(t, priv, 1, uint32(babySteps))
	ciphertext1, err := EncryptUint32(rand.Reader, &priv.PublicKey, 0xffffffff)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext2, err := EncryptUint32(rand.Reader, &priv.PublicKey, 0xff)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.Add(ciphertext1, ciphertext2)
	_, err = DecryptUint32(priv, ciphertext)
	if err == nil || err != ErrOverflow {
		t.Fatal("should be overflow error")
	}
}

func testAddInt32(t *testing.T, priv *sm2.PrivateKey, m1, m2 int32) {
	ciphertext1, err := EncryptInt32(rand.Reader, &priv.PublicKey, m1)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext2, err := EncryptInt32(rand.Reader, &priv.PublicKey, m2)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.Add(ciphertext1, ciphertext2)
	v, err := DecryptInt32(priv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if v != m1+m2 {
		t.Fatalf("expected %x, got %x", m1+m2, v)
	}
}

func TestAddInt32(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	testAddInt32(t, priv, 2, -3)
	testAddInt32(t, priv, 3, -2)
	testAddInt32(t, priv, 1, int32(babySteps))
	testAddInt32(t, priv, 1, int32(-babySteps))
	ciphertext1, err := EncryptInt32(rand.Reader, &priv.PublicKey, 0x7fffffff)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext2, err := EncryptInt32(rand.Reader, &priv.PublicKey, 0xff)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.Add(ciphertext1, ciphertext2)
	_, err = DecryptInt32(priv, ciphertext)
	if err == nil || err != ErrOverflow {
		t.Fatal("should be overflow error")
	}
}

func testSubUint32(t *testing.T, priv *sm2.PrivateKey, m1, m2 uint32) {
	ciphertext1, err := EncryptUint32(rand.Reader, &priv.PublicKey, m1)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext2, err := EncryptUint32(rand.Reader, &priv.PublicKey, m2)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.Sub(ciphertext1, ciphertext2)
	v, err := DecryptUint32(priv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if v != m1-m2 {
		t.Fatalf("expected %x, got %x", m1-m2, v)
	}
}

func TestSubUint32(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	testSubUint32(t, priv, 0, 0)
	testSubUint32(t, priv, 2, 0)
	testSubUint32(t, priv, 2, 1)
	testSubUint32(t, priv, uint32(babySteps), 1)
	ciphertext1, err := EncryptUint32(rand.Reader, &priv.PublicKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext2, err := EncryptUint32(rand.Reader, &priv.PublicKey, 2)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.Sub(ciphertext1, ciphertext2)
	_, err = DecryptUint32(priv, ciphertext)
	if err == nil || err != ErrOverflow {
		t.Fatal("should be overflow error")
	}
}

func testSubInt32(t *testing.T, priv *sm2.PrivateKey, m1, m2 int32) {
	ciphertext1, err := EncryptInt32(rand.Reader, &priv.PublicKey, m1)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext2, err := EncryptInt32(rand.Reader, &priv.PublicKey, m2)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.Sub(ciphertext1, ciphertext2)
	v, err := DecryptInt32(priv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if v != m1-m2 {
		t.Fatalf("expected %x, got %x", m1-m2, v)
	}
}

func TestSubInt32(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	testSubInt32(t, priv, 1, 2)
	testSubInt32(t, priv, 2, 1)
	testSubInt32(t, priv, int32(babySteps), 1)
	testSubInt32(t, priv, 1, int32(babySteps))
	ciphertext1, err := EncryptInt32(rand.Reader, &priv.PublicKey, -1)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext2, err := EncryptInt32(rand.Reader, &priv.PublicKey, 0x7fffffff)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.Sub(ciphertext1, ciphertext2)
	_, err = DecryptInt32(priv, ciphertext)
	if err == nil || err != ErrOverflow {
		t.Fatal("should be overflow error")
	}
}

func testScalarMultUint32(t *testing.T, priv *sm2.PrivateKey, m1, m2 uint32) {
	ciphertext1, err := EncryptUint32(rand.Reader, &priv.PublicKey, m1)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.ScalarMultUint32(ciphertext1, m2)
	v, err := DecryptUint32(priv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if v != m1*m2 {
		t.Fatalf("expected %x, got %x", m1*m2, v)
	}
}

func TestScalarMultUint32(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	testScalarMultUint32(t, priv, 0, 5)
	testScalarMultUint32(t, priv, 4, 5)
	testScalarMultUint32(t, priv, 4, uint32(babySteps))
	ciphertext1, err := EncryptUint32(rand.Reader, &priv.PublicKey, 0xefffffff)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.ScalarMultUint32(ciphertext1, 2)
	_, err = DecryptUint32(priv, ciphertext)
	if err == nil || err != ErrOverflow {
		t.Fatal("should be overflow error")
	}
}

func testScalarMultInt32(t *testing.T, priv *sm2.PrivateKey, m1, m2 int32) {
	ciphertext1, err := EncryptInt32(rand.Reader, &priv.PublicKey, m1)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.ScalarMultInt32(ciphertext1, m2)
	v, err := DecryptInt32(priv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if v != m1*m2 {
		t.Fatalf("expected %x, got %x", m1*m2, v)
	}
}

func TestScalarMultInt32(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	testScalarMultInt32(t, priv, 4, -5)
	testScalarMultInt32(t, priv, -4, 5)
	testScalarMultInt32(t, priv, -4, int32(babySteps))
	ciphertext1, err := EncryptInt32(rand.Reader, &priv.PublicKey, 0x1fffffff)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.ScalarMultInt32(ciphertext1, 7)
	_, err = DecryptInt32(priv, ciphertext)
	if err == nil || err != ErrOverflow {
		t.Fatal("should be overflow error")
	}
	ciphertext.ScalarMultInt32(ciphertext1, -7)
	_, err = DecryptInt32(priv, ciphertext)
	if err == nil || err != ErrOverflow {
		t.Fatal("should be overflow error")
	}
}

func TestMarshal(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	ciphertext, err := EncryptInt32(rand.Reader, &priv.PublicKey, 0x1fffffff)
	if err != nil {
		t.Fatal(err)
	}
	der, err := Marshal(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext2, err := Unmarshal(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ciphertext.c1, ciphertext2.c1) || !bytes.Equal(ciphertext.c2, ciphertext2.c2) {
		t.Fatal("not same")
	}
}
