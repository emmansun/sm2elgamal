package sm2elgamal

import (
	"crypto/rand"
	"testing"

	"github.com/emmansun/gmsm/sm2"
)

func TestLookupTableSize(t *testing.T) {
	size := LookupTableSize()
	if size != (1<<21)-1 {
		t.Errorf("expected %d, got %d", (1<<21)-2, size)
	}
}

func testEncryptDecrypt(t *testing.T, priv *sm2.PrivateKey, m uint32) {
	ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, m)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Decrypt(priv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if v != m {
		t.Fatalf("expected %x, got %x", m, v)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	for i := 0; i < 10; i++ {
		testEncryptDecrypt(t, priv, uint32(i))
	}
	for i := 0xffffffff; i > 0xfffffff0; i-- {
		testEncryptDecrypt(t, priv, uint32(i))
	}

	for i := 1; i < 10; i++ {
		testEncryptDecrypt(t, priv, uint32(i*babySteps))
	}
}

func testEncryptDecryptSigned(t *testing.T, priv *sm2.PrivateKey, m int32) {
	ciphertext, err := EncryptSigned(rand.Reader, &priv.PublicKey, m)
	if err != nil {
		t.Fatal(err)
	}
	v, err := DecryptSigned(priv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if v != m {
		t.Fatalf("expected %x, got %x", m, v)
	}
}

func TestEncryptDecryptSigned(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	for i := 0; i < 10; i++ {
		testEncryptDecryptSigned(t, priv, int32(i))
	}

	for i := -10; i < 0; i++ {
		testEncryptDecryptSigned(t, priv, int32(i))
	}

	testEncryptDecryptSigned(t, priv, 0x7fffffff)
	testEncryptDecryptSigned(t, priv, -0x7fffffff)

	for i := 1; i < 10; i++ {
		testEncryptDecryptSigned(t, priv, int32(i*babySteps))
		testEncryptDecryptSigned(t, priv, int32(-i*babySteps))
	}
}

func testAdd(t *testing.T, priv *sm2.PrivateKey, m1, m2 uint32) {
	ciphertext1, err := Encrypt(rand.Reader, &priv.PublicKey, m1)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext2, err := Encrypt(rand.Reader, &priv.PublicKey, m2)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.Add(ciphertext1, ciphertext2)
	v, err := Decrypt(priv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if v != m1+m2 {
		t.Fatalf("expected %x, got %x", m1+m2, v)
	}
}

func TestAdd(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	testAdd(t, priv, 0, 0)
	testAdd(t, priv, 0, 2)
	testAdd(t, priv, 1, 2)
	testAdd(t, priv, 1, uint32(babySteps))
	ciphertext1, err := Encrypt(rand.Reader, &priv.PublicKey, 0xffffffff)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext2, err := Encrypt(rand.Reader, &priv.PublicKey, 0xff)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.Add(ciphertext1, ciphertext2)
	_, err = Decrypt(priv, ciphertext)
	if err == nil || err != ErrOverflow {
		t.Fatal("should be overflow error")
	}
}

func testAddSigned(t *testing.T, priv *sm2.PrivateKey, m1, m2 int32) {
	ciphertext1, err := EncryptSigned(rand.Reader, &priv.PublicKey, m1)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext2, err := EncryptSigned(rand.Reader, &priv.PublicKey, m2)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.Add(ciphertext1, ciphertext2)
	v, err := DecryptSigned(priv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if v != m1+m2 {
		t.Fatalf("expected %x, got %x", m1+m2, v)
	}
}

func TestAddSigned(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	testAddSigned(t, priv, 2, -3)
	testAddSigned(t, priv, 3, -2)
	testAddSigned(t, priv, 1, int32(babySteps))
	testAddSigned(t, priv, 1, int32(-babySteps))
	ciphertext1, err := EncryptSigned(rand.Reader, &priv.PublicKey, 0x7fffffff)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext2, err := EncryptSigned(rand.Reader, &priv.PublicKey, 0xff)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.Add(ciphertext1, ciphertext2)
	_, err = DecryptSigned(priv, ciphertext)
	if err == nil || err != ErrOverflow {
		t.Fatal("should be overflow error")
	}
}

func testSub(t *testing.T, priv *sm2.PrivateKey, m1, m2 uint32) {
	ciphertext1, err := Encrypt(rand.Reader, &priv.PublicKey, m1)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext2, err := Encrypt(rand.Reader, &priv.PublicKey, m2)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.Sub(ciphertext1, ciphertext2)
	v, err := Decrypt(priv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if v != m1-m2 {
		t.Fatalf("expected %x, got %x", m1-m2, v)
	}
}

func TestSub(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	testSub(t, priv, 0, 0)
	testSub(t, priv, 2, 0)
	testSub(t, priv, 2, 1)
	testSub(t, priv, uint32(babySteps), 1)
	ciphertext1, err := Encrypt(rand.Reader, &priv.PublicKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext2, err := Encrypt(rand.Reader, &priv.PublicKey, 2)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.Sub(ciphertext1, ciphertext2)
	_, err = Decrypt(priv, ciphertext)
	if err == nil || err != ErrOverflow {
		t.Fatal("should be overflow error")
	}
}

func testSubSigned(t *testing.T, priv *sm2.PrivateKey, m1, m2 int32) {
	ciphertext1, err := EncryptSigned(rand.Reader, &priv.PublicKey, m1)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext2, err := EncryptSigned(rand.Reader, &priv.PublicKey, m2)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.Sub(ciphertext1, ciphertext2)
	v, err := DecryptSigned(priv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if v != m1-m2 {
		t.Fatalf("expected %x, got %x", m1-m2, v)
	}
}

func TestSubSigned(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	testSubSigned(t, priv, 1, 2)
	testSubSigned(t, priv, 2, 1)
	testSubSigned(t, priv, int32(babySteps), 1)
	testSubSigned(t, priv, 1, int32(babySteps))
	ciphertext1, err := EncryptSigned(rand.Reader, &priv.PublicKey, -1)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext2, err := EncryptSigned(rand.Reader, &priv.PublicKey, 0x7fffffff)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.Sub(ciphertext1, ciphertext2)
	_, err = DecryptSigned(priv, ciphertext)
	if err == nil || err != ErrOverflow {
		t.Fatal("should be overflow error")
	}
}

func testScalarMult(t *testing.T, priv *sm2.PrivateKey, m1, m2 uint32) {
	ciphertext1, err := Encrypt(rand.Reader, &priv.PublicKey, m1)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.ScalarMult(ciphertext1, m2)
	v, err := Decrypt(priv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if v != m1*m2 {
		t.Fatalf("expected %x, got %x", m1*m2, v)
	}
}

func TestScalarMult(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	testScalarMult(t, priv, 0, 5)
	testScalarMult(t, priv, 4, 5)
	testScalarMult(t, priv, 4, uint32(babySteps))
	ciphertext1, err := Encrypt(rand.Reader, &priv.PublicKey, 0xefffffff)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.ScalarMult(ciphertext1, 2)
	_, err = Decrypt(priv, ciphertext)
	if err == nil || err != ErrOverflow {
		t.Fatal("should be overflow error")
	}
}

func testScalarMultSigned(t *testing.T, priv *sm2.PrivateKey, m1, m2 int32) {
	ciphertext1, err := EncryptSigned(rand.Reader, &priv.PublicKey, m1)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.ScalarMultSigned(ciphertext1, m2)
	v, err := DecryptSigned(priv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if v != m1*m2 {
		t.Fatalf("expected %x, got %x", m1*m2, v)
	}
}

func TestScalarMultSigned(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)
	testScalarMultSigned(t, priv, 4, -5)
	testScalarMultSigned(t, priv, -4, 5)
	testScalarMultSigned(t, priv, -4, int32(babySteps))
	ciphertext1, err := EncryptSigned(rand.Reader, &priv.PublicKey, 0x1fffffff)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := &Ciphertext{}
	ciphertext.ScalarMultSigned(ciphertext1, 7)
	_, err = DecryptSigned(priv, ciphertext)
	if err == nil || err != ErrOverflow {
		t.Fatal("should be overflow error")
	}
	ciphertext.ScalarMultSigned(ciphertext1, -7)
	_, err = DecryptSigned(priv, ciphertext)
	if err == nil || err != ErrOverflow {
		t.Fatal("should be overflow error")
	}
}
