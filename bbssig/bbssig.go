// Package bbssig implements the BBS, short group signatures scheme as
// detailed in http://crypto.stanford.edu/~dabo/papers/groupsigs.pdf.
//
// Group signatures are a variation on traditional public-key signatures in
// that there are many different private-keys that can create valid signatures.
// Holders of these private keys are called members, and a signature from any
// member is indistinguishable from any other, from the point of view of the
// public key.
//
// However, there is also a group private key, which differs from the member
// private keys. The group private key can create new member private keys, and
// can open signatures and discover which member created the signature.
//
// This implementation of group signatures also supports revocation of member
// private keys. The group private key can produce a public 'revocation' of a
// member private key. A revocation can be combined with the group, and with
// each member private key to produce an updated group and updated private keys.
// Signatures under the old keys are invalid under the new but, critically, the
// revoked private key cannot be updated due to a divisor becoming zero.
//
// This form of revocation is complicated, but avoids deanonymising all
// previous signatures from the revoked member.
package bbssig

import (
	"crypto/rand"
	"hash"
	"io"
	"math/big"

	"golang.org/x/crypto/bn256"
)

// SignatureSize is the size, in bytes, of the signatures produced by this
// package. (3072 bits.)
const SignatureSize = 12 * 32

// Group represents a public key in the group signature scheme. Signatures by
// the group members can be verified given the Group.
type Group struct {
	g1, h, u, v           *bn256.G1
	g2, w                 *bn256.G2
	ehw, ehg2, minusEg1g2 *bn256.GT
}

// Marshal serializes g to a slice of bytes, suitable for Unmarshal.
func (g *Group) Marshal() []byte {
	out := make([]byte, 0, 4*2*32+2*2*2*32)
	out = append(out, g.g1.Marshal()...)
	out = append(out, g.h.Marshal()...)
	out = append(out, g.u.Marshal()...)
	out = append(out, g.v.Marshal()...)
	out = append(out, g.g2.Marshal()...)
	out = append(out, g.w.Marshal()...)
	return out
}

// Unmarshal sets g to the result of unmarshaling b and returns both g and a
// bool that is true on success. Since Group contains some precomputed values
// that aren't included in the serialisation, Unmarshal does significant
// computation.
func (g *Group) Unmarshal(b []byte) (*Group, bool) {
	if len(b) != 4*2*32+2*2*2*32 {
		return nil, false
	}
	var ok bool
	if g.g1, ok = new(bn256.G1).Unmarshal(b[0*2*32 : 1*2*32]); !ok {
		return nil, false
	}
	if g.h, ok = new(bn256.G1).Unmarshal(b[1*2*32 : 2*2*32]); !ok {
		return nil, false
	}
	if g.u, ok = new(bn256.G1).Unmarshal(b[2*2*32 : 3*2*32]); !ok {
		return nil, false
	}
	if g.v, ok = new(bn256.G1).Unmarshal(b[3*2*32 : 4*2*32]); !ok {
		return nil, false
	}

	b = b[4*2*32:]
	if g.g2, ok = new(bn256.G2).Unmarshal(b[0*2*2*32 : 1*2*2*32]); !ok {
		return nil, false
	}
	if g.w, ok = new(bn256.G2).Unmarshal(b[1*2*2*32 : 2*2*2*32]); !ok {
		return nil, false
	}

	g.precompute()
	return g, true
}

func (g *Group) precompute() {
	g.ehw = bn256.Pair(g.h, g.w)
	g.ehg2 = bn256.Pair(g.h, g.g2)

	t := bn256.Pair(g.g1, g.g2)
	g.minusEg1g2 = new(bn256.GT).Neg(t)
}

// PrivateKey represents a group private key. The holder of the private key can
// create new group members and can reveal which member created a given
// signature.
type PrivateKey struct {
	*Group
	xi1, xi2 *big.Int
	gamma    *big.Int
}

// Marshal serializes priv to a slice of bytes, suitable for Unmarshal.
func (priv *PrivateKey) Marshal() []byte {
	out := make([]byte, 0, 3*32)
	out = appendN(out, priv.xi1)
	out = appendN(out, priv.xi2)
	out = appendN(out, priv.gamma)
	return out
}

// Unmarshal sets priv to the result of unmarshaling b and returns both priv
// and a bool that is true on success.
func (priv *PrivateKey) Unmarshal(g *Group, b []byte) (*PrivateKey, bool) {
	if len(b) != 3*32 {
		return nil, false
	}

	priv.Group = g
	priv.xi1 = new(big.Int).SetBytes(b[0*32 : 1*32])
	priv.xi2 = new(big.Int).SetBytes(b[1*32 : 2*32])
	priv.gamma = new(big.Int).SetBytes(b[2*32 : 3*32])

	return priv, true
}

// MemberKey represents a member private key. It is capable of signing messages
// such that nobody, save the holder of the group private key, can determine
// which member of the group made the signature.
type MemberKey struct {
	*Group
	x *big.Int
	a *bn256.G1
}

// Tag returns an opaque byte slice that identifies the member private key for
// the purposes of comparing against the result of Open.
func (mem *MemberKey) Tag() []byte {
	return mem.a.Marshal()
}

// Marshal serializes mem to a slice of bytes, suitable for Unmarshal.
func (mem *MemberKey) Marshal() []byte {
	out := make([]byte, 0, 3*32)
	out = appendN(out, mem.x)
	out = append(out, mem.a.Marshal()...)
	return out
}

// Unmarshal sets mem to the result of unmarshaling b and returns both mem and
// a bool that is true on success.
func (mem *MemberKey) Unmarshal(g *Group, b []byte) (*MemberKey, bool) {
	if len(b) != 3*32 {
		return nil, false
	}

	var ok bool
	mem.Group = g
	mem.x = new(big.Int).SetBytes(b[0*32 : 1*32])
	if mem.a, ok = new(bn256.G1).Unmarshal(b[1*32:]); !ok {
		return nil, false
	}

	return mem, true
}

func randomZp(r io.Reader) (*big.Int, error) {
	for {
		n, err := rand.Int(r, bn256.Order)
		if err != nil {
			return nil, err
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}

	panic("unreachable")
}

// GenerateGroup generates a new group and group private key.
func GenerateGroup(r io.Reader) (*PrivateKey, error) {
	priv := new(PrivateKey)
	priv.Group = new(Group)
	var err error

	if _, priv.g1, err = bn256.RandomG1(r); err != nil {
		return nil, err
	}
	if _, priv.g2, err = bn256.RandomG2(r); err != nil {
		return nil, err
	}
	if _, priv.h, err = bn256.RandomG1(r); err != nil {
		return nil, err
	}
	if priv.xi1, err = randomZp(r); err != nil {
		return nil, err
	}
	if priv.xi2, err = randomZp(r); err != nil {
		return nil, err
	}

	z0 := new(big.Int).ModInverse(priv.xi1, bn256.Order)
	priv.u = new(bn256.G1).ScalarMult(priv.h, z0)

	z0.ModInverse(priv.xi2, bn256.Order)
	priv.v = new(bn256.G1).ScalarMult(priv.h, z0)

	priv.gamma, err = randomZp(r)
	if err != nil {
		return nil, err
	}
	priv.w = new(bn256.G2).ScalarMult(priv.g2, priv.gamma)
	priv.precompute()

	return priv, nil
}

// NewMember creates a new member private key for the group.
func (priv *PrivateKey) NewMember(r io.Reader) (*MemberKey, error) {
	mem := new(MemberKey)
	var err error

	mem.Group = priv.Group
	mem.x, err = randomZp(r)
	if err != nil {
		return nil, err
	}

	s := new(big.Int).Add(priv.gamma, mem.x)
	s.ModInverse(s, bn256.Order)
	mem.a = new(bn256.G1).ScalarMult(priv.g1, s)

	return mem, nil
}

// Sign computes a group signature of digest using the given hash function.
func (mem *MemberKey) Sign(r io.Reader, digest []byte, hashFunc hash.Hash) ([]byte, error) {
	var rnds [7]*big.Int
	for i := range rnds {
		var err error
		rnds[i], err = randomZp(r)
		if err != nil {
			return nil, err
		}
	}
	alpha := rnds[0]
	beta := rnds[1]

	t1 := new(bn256.G1).ScalarMult(mem.u, alpha)
	t2 := new(bn256.G1).ScalarMult(mem.v, beta)

	tmp := new(big.Int).Add(alpha, beta)
	t3 := new(bn256.G1).ScalarMult(mem.h, tmp)
	t3.Add(t3, mem.a)

	delta1 := new(big.Int).Mul(mem.x, alpha)
	delta1.Mod(delta1, bn256.Order)
	delta2 := new(big.Int).Mul(mem.x, beta)
	delta2.Mod(delta2, bn256.Order)

	ralpha := rnds[2]
	rbeta := rnds[3]
	rx := rnds[4]
	rdelta1 := rnds[5]
	rdelta2 := rnds[6]

	r1 := new(bn256.G1).ScalarMult(mem.u, ralpha)
	r2 := new(bn256.G1).ScalarMult(mem.v, rbeta)

	r3 := bn256.Pair(t3, mem.g2)
	r3.ScalarMult(r3, rx)

	tmp.Neg(ralpha)
	tmp.Sub(tmp, rbeta)
	tmp.Mod(tmp, bn256.Order)
	tmpgt := new(bn256.GT).ScalarMult(mem.ehw, tmp)
	r3.Add(r3, tmpgt)

	tmp.Neg(rdelta1)
	tmp.Sub(tmp, rdelta2)
	tmp.Mod(tmp, bn256.Order)
	tmpgt.ScalarMult(mem.ehg2, tmp)
	r3.Add(r3, tmpgt)

	r4 := new(bn256.G1).ScalarMult(t1, rx)
	tmp.Neg(rdelta1)
	tmp.Add(tmp, bn256.Order)
	tmpg := new(bn256.G1).ScalarMult(mem.u, tmp)
	r4.Add(r4, tmpg)

	r5 := new(bn256.G1).ScalarMult(t2, rx)
	tmp.Neg(rdelta2)
	tmp.Add(tmp, bn256.Order)
	tmpg.ScalarMult(mem.v, tmp)
	r5.Add(r5, tmpg)

	t1Bytes := t1.Marshal()
	t2Bytes := t2.Marshal()
	t3Bytes := t3.Marshal()

	hashFunc.Reset()
	hashFunc.Write(digest)
	hashFunc.Write(t1Bytes)
	hashFunc.Write(t2Bytes)
	hashFunc.Write(t3Bytes)
	hashFunc.Write(r1.Marshal())
	hashFunc.Write(r2.Marshal())
	hashFunc.Write(r3.Marshal())
	hashFunc.Write(r4.Marshal())
	hashFunc.Write(r5.Marshal())
	c := new(big.Int).SetBytes(hashFunc.Sum(nil))
	c.Mod(c, bn256.Order)

	salpha := new(big.Int).Mul(c, alpha)
	salpha.Add(salpha, ralpha)
	salpha.Mod(salpha, bn256.Order)

	sbeta := new(big.Int).Mul(c, beta)
	sbeta.Add(sbeta, rbeta)
	sbeta.Mod(sbeta, bn256.Order)

	sx := new(big.Int).Mul(c, mem.x)
	sx.Add(sx, rx)
	sx.Mod(sx, bn256.Order)

	sdelta1 := new(big.Int).Mul(c, delta1)
	sdelta1.Add(sdelta1, rdelta1)
	sdelta1.Mod(sdelta1, bn256.Order)

	sdelta2 := new(big.Int).Mul(c, delta2)
	sdelta2.Add(sdelta2, rdelta2)
	sdelta2.Mod(sdelta2, bn256.Order)

	sig := make([]byte, 0, SignatureSize)
	sig = append(sig, t1Bytes...)
	sig = append(sig, t2Bytes...)
	sig = append(sig, t3Bytes...)
	sig = appendN(sig, c)
	sig = appendN(sig, salpha)
	sig = appendN(sig, sbeta)
	sig = appendN(sig, sx)
	sig = appendN(sig, sdelta1)
	sig = appendN(sig, sdelta2)

	return sig, nil
}

// Verify verifies that sig is a valid signature of digest using the given hash
// function.
func (g *Group) Verify(digest []byte, hashFunc hash.Hash, sig []byte) bool {
	if len(sig) != SignatureSize {
		return false
	}

	t1, ok := new(bn256.G1).Unmarshal(sig[:2*32])
	if !ok {
		return false
	}
	t2, ok := new(bn256.G1).Unmarshal(sig[2*32 : 4*32])
	if !ok {
		return false
	}
	t3, ok := new(bn256.G1).Unmarshal(sig[4*32 : 6*32])
	if !ok {
		return false
	}
	c := new(big.Int).SetBytes(sig[6*32 : 7*32])
	salpha := new(big.Int).SetBytes(sig[7*32 : 8*32])
	sbeta := new(big.Int).SetBytes(sig[8*32 : 9*32])
	sx := new(big.Int).SetBytes(sig[9*32 : 10*32])
	sdelta1 := new(big.Int).SetBytes(sig[10*32 : 11*32])
	sdelta2 := new(big.Int).SetBytes(sig[11*32 : 12*32])

	r1 := new(bn256.G1).ScalarMult(g.u, salpha)
	tmp := new(big.Int).Neg(c)
	tmp.Add(tmp, bn256.Order)
	tmpg := new(bn256.G1).ScalarMult(t1, tmp)
	r1.Add(r1, tmpg)

	r2 := new(bn256.G1).ScalarMult(g.v, sbeta)
	tmpg.ScalarMult(t2, tmp)
	r2.Add(r2, tmpg)

	r4 := new(bn256.G1).ScalarMult(t1, sx)
	tmp.Neg(sdelta1)
	tmp.Add(tmp, bn256.Order)
	tmpg.ScalarMult(g.u, tmp)
	r4.Add(r4, tmpg)

	r5 := new(bn256.G1).ScalarMult(t2, sx)
	tmp.Neg(sdelta2)
	tmp.Add(tmp, bn256.Order)
	tmpg.ScalarMult(g.v, tmp)
	r5.Add(r5, tmpg)

	r3 := bn256.Pair(t3, g.g2)
	r3.ScalarMult(r3, sx)

	tmp.Neg(salpha)
	tmp.Sub(tmp, sbeta)
	tmp.Mod(tmp, bn256.Order)
	tmpgt := new(bn256.GT).ScalarMult(g.ehw, tmp)
	r3.Add(r3, tmpgt)

	tmp.Neg(sdelta1)
	tmp.Sub(tmp, sdelta2)
	tmp.Mod(tmp, bn256.Order)
	tmpgt.ScalarMult(g.ehg2, tmp)
	r3.Add(r3, tmpgt)

	et3w := bn256.Pair(t3, g.w)
	et3w.Add(et3w, g.minusEg1g2)
	et3w.ScalarMult(et3w, c)
	r3.Add(r3, et3w)

	hashFunc.Reset()
	hashFunc.Write(digest)
	hashFunc.Write(t1.Marshal())
	hashFunc.Write(t2.Marshal())
	hashFunc.Write(t3.Marshal())
	hashFunc.Write(r1.Marshal())
	hashFunc.Write(r2.Marshal())
	hashFunc.Write(r3.Marshal())
	hashFunc.Write(r4.Marshal())
	hashFunc.Write(r5.Marshal())
	cprime := new(big.Int).SetBytes(hashFunc.Sum(nil))
	cprime.Mod(cprime, bn256.Order)

	return cprime.Cmp(c) == 0
}

// Open reveals which member private key made the given signature. The return
// value will match the result of calling Tag on the member private key in
// question.
func (priv *PrivateKey) Open(sig []byte) ([]byte, bool) {
	if len(sig) != 12*32 {
		return nil, false
	}

	t1, ok := new(bn256.G1).Unmarshal(sig[:2*32])
	if !ok {
		return nil, false
	}
	t2, ok := new(bn256.G1).Unmarshal(sig[2*32 : 4*32])
	if !ok {
		return nil, false
	}
	t3, ok := new(bn256.G1).Unmarshal(sig[4*32 : 6*32])
	if !ok {
		return nil, false
	}

	a := new(bn256.G1).ScalarMult(t1, priv.xi1)
	b := new(bn256.G1).ScalarMult(t2, priv.xi2)
	a.Add(a, b)
	a.Neg(a)
	a.Add(t3, a)

	return a.Marshal(), true
}

// Revocation represents a revocation of a member private key. A Revocation can
// be applied to update a member private key and also to a group to create a
// new group that does not include the revoked member.
type Revocation struct {
	x     *big.Int
	a     *bn256.G1
	aStar *bn256.G2
}

// GenerateRevocation creates a Revocation that revokes the given member
// private key.
func (priv *PrivateKey) GenerateRevocation(mem *MemberKey) *Revocation {
	s := new(big.Int).Add(priv.gamma, mem.x)
	s.ModInverse(s, bn256.Order)
	aStar := new(bn256.G2).ScalarMult(priv.g2, s)

	return &Revocation{mem.x, mem.a, aStar}
}

// Marshal serializes r to a slice of bytes, suitable for Unmarshal.
func (r *Revocation) Marshal() []byte {
	ret := make([]byte, 0, 7*32)
	ret = append(ret, r.a.Marshal()...)
	ret = appendN(ret, r.x)
	ret = append(ret, r.aStar.Marshal()...)
	return ret
}

func (r *Revocation) Unmarshal(b []byte) (*Revocation, bool) {
	if len(b) != 7*32 {
		return nil, false
	}

	var ok bool
	r.a, ok = new(bn256.G1).Unmarshal(b[:2*32])
	if !ok {
		return nil, false
	}
	r.x = new(big.Int).SetBytes(b[2*32 : 3*32])
	r.aStar, ok = new(bn256.G2).Unmarshal(b[3*32 : 7*32])
	if !ok {
		return nil, false
	}
	return r, true
}

// Update alters g to create a new Group that includes all previous members,
// save a specifically revoked member.
func (g *Group) Update(r *Revocation) {
	tmp := new(big.Int).Neg(r.x)
	tmp.Add(tmp, bn256.Order)
	t := new(bn256.G2).ScalarMult(r.aStar, tmp)
	g.w.Add(g.g2, t)

	g.g1 = r.a
	g.g2 = r.aStar

	g.precompute()
}

// Update alters mem to create a member private key for an updated Group. (Note
// that the Group of mem must also be updated.) This functions returns false if
// mem is the member private key that has been revoked.
func (mem *MemberKey) Update(r *Revocation) bool {
	if mem.x.Cmp(r.x) == 0 {
		return false
	}

	d := new(big.Int).Sub(mem.x, r.x)
	d.Mod(d, bn256.Order)
	d.ModInverse(d, bn256.Order)

	newA := new(bn256.G1).ScalarMult(r.a, d)
	t := new(bn256.G1).ScalarMult(mem.a, d)
	t.Neg(t)
	newA.Add(newA, t)

	mem.a = newA
	return true
}

func appendN(b []byte, n *big.Int) []byte {
	bytes := n.Bytes()
	if len(bytes) > 32 {
		panic("bad value passed to appendN")
	}

	for i := len(bytes); i < 32; i++ {
		b = append(b, 0)
	}
	return append(b, bytes...)
}
