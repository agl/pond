package bn256cgo

import (
	"bytes"
	"math/big"
	"testing"

	"golang.org/x/crypto/bn256"
)

func TestPowers(t *testing.T) {
	power := big.NewInt(1)
	bigOne := big.NewInt(1)

	for i := 0; i < 150; i++ {
		a := new(G1).ScalarBaseMult(power).Marshal()
		b := new(bn256.G1).ScalarBaseMult(power).Marshal()
		if !bytes.Equal(a, b) {
			t.Errorf("failed at power %s: %x vs %x", power, a, b)
		}
		power.Lsh(power, 1)
		if i&1 == 1 {
			power.Add(power, bigOne)
		}
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	a := new(G1).ScalarBaseMult(big.NewInt(66))
	serialise1 := a.Marshal()
	b, ok := new(G1).Unmarshal(serialise1)
	if !ok {
		t.Fatalf("Unmarshal failed")
	}
	serialise2 := b.Marshal()
	if !bytes.Equal(serialise1, serialise2) {
		t.Errorf("Marshal/Unmarshal round trip failed, got: %x want: %x", serialise2, serialise1)
	}
}

func TestPowersG2(t *testing.T) {
	power := big.NewInt(1)
	bigOne := big.NewInt(1)

	for i := 0; i < 150; i++ {
		a := new(G2).ScalarBaseMult(power).Marshal()
		b := new(bn256.G2).ScalarBaseMult(power).Marshal()
		if !bytes.Equal(a, b) {
			t.Errorf("failed at power %s: %x vs %x", power, a, b)
		}
		power.Lsh(power, 1)
		if i&1 == 1 {
			power.Add(power, bigOne)
		}
	}
}

func TestMarshalUnmarshalG2(t *testing.T) {
	a := new(G2).ScalarBaseMult(big.NewInt(66))
	serialise1 := a.Marshal()
	b, ok := new(G2).Unmarshal(serialise1)
	if !ok {
		t.Fatalf("Unmarshal failed")
	}
	serialise2 := b.Marshal()
	if !bytes.Equal(serialise1, serialise2) {
		t.Errorf("Marshal/Unmarshal round trip failed, got: %x want: %x", serialise2, serialise1)
	}
}

func TestMarshalUnmarshalGT(t *testing.T) {
	a := Pair(new(G1).ScalarBaseMult(big.NewInt(44)), new(G2).ScalarBaseMult(big.NewInt(22)))
	serialise1 := a.Marshal()
	b, ok := new(GT).Unmarshal(serialise1)
	if !ok {
		t.Fatalf("Unmarshal failed")
	}
	serialise2 := b.Marshal()
	if !bytes.Equal(serialise1, serialise2) {
		t.Errorf("Marshal/Unmarshal round trip failed, got:\n%x\nwant:\n%x", serialise2, serialise1)
	}
}

func TestPairing(t *testing.T) {
	a := bn256.Pair(new(bn256.G1).ScalarBaseMult(big.NewInt(2)), new(bn256.G2).ScalarBaseMult(big.NewInt(1))).Marshal()
	b := Pair(new(G1).ScalarBaseMult(big.NewInt(2)), new(G2).ScalarBaseMult(big.NewInt(1))).Marshal()
	base := Pair(new(G1).ScalarBaseMult(big.NewInt(1)), new(G2).ScalarBaseMult(big.NewInt(1)))
	b2 := new(GT).Add(base, base).Marshal()

	if !bytes.Equal(a, b) {
		t.Errorf("Pairings differ\ngot:  %x\nwant: %x", a, b)
	}
	if !bytes.Equal(b, b2) {
		t.Errorf("Pair(2,1) != 2*Pair(1,1)\ngot:  %x\nwant: %x", b, b2)
	}
}
