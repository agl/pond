// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bn256cgo

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
)

func TestTripartiteDiffieHellman(t *testing.T) {
	a, _ := rand.Int(rand.Reader, Order)
	b, _ := rand.Int(rand.Reader, Order)
	c, _ := rand.Int(rand.Reader, Order)

	pa, _ := new(G1).Unmarshal(new(G1).ScalarBaseMult(a).Marshal())
	qa, _ := new(G2).Unmarshal(new(G2).ScalarBaseMult(a).Marshal())
	pb, _ := new(G1).Unmarshal(new(G1).ScalarBaseMult(b).Marshal())
	qb, _ := new(G2).Unmarshal(new(G2).ScalarBaseMult(b).Marshal())
	pc, _ := new(G1).Unmarshal(new(G1).ScalarBaseMult(c).Marshal())
	qc, _ := new(G2).Unmarshal(new(G2).ScalarBaseMult(c).Marshal())

	k1 := Pair(pb, qc)
	k1.ScalarMult(k1, a)
	k1Bytes := k1.Marshal()

	k2 := Pair(pc, qa)
	k2.ScalarMult(k2, b)
	k2Bytes := k2.Marshal()

	k3 := Pair(pa, qb)
	k3.ScalarMult(k3, c)
	k3Bytes := k3.Marshal()

	if !bytes.Equal(k1Bytes, k2Bytes) || !bytes.Equal(k2Bytes, k3Bytes) {
		t.Errorf("keys didn't agree")
	}
}

func BenchmarkPairing(b *testing.B) {
	g1 := new(G1).ScalarBaseMult(big.NewInt(44))
	g2 := new(G2).ScalarBaseMult(big.NewInt(55))
	for i := 0; i < b.N; i++ {
		Pair(g1, g2)
	}
}
