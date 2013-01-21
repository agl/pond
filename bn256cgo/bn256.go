/*
Package bn256cgo is a drop in replacement for the bn256 package from go.crypto.

It should be about 10x faster than the pure-Go version when run on an amd64
based system. It wraps a patched version of
http://cryptojedi.org/crypto/#dclxvi.

See the original package for documentation.

[1] http://cryptojedi.org/papers/dclxvi-20100714.pdf
*/
package bn256cgo

import (
	"crypto/rand"
	"io"
	"math/big"
	"strings"
	"unsafe"
)

// #cgo CFLAGS: -I/home/agl/devel/dclxvi
// #cgo LDFLAGS: -L/home/agl/devel/dclxvi -ldclxvipairing -lm
/*
#include <stdio.h>
#include <string.h>

#include "curvepoint_fp.h"
#include "optate.h"
#include "twistpoint_fp2.h"
#include "fp12e.h"

extern const curvepoint_fp_t bn_curvegen;
extern const twistpoint_fp2_t bn_twistgen;

struct g1 {
	curvepoint_fp_t p;
};

void g1_set_gen(struct g1 *a) {
	curvepoint_fp_set(a->p, bn_curvegen);
}

void g1_double(struct g1 *a) {
	curvepoint_fp_double(a->p, a->p);
}

void g1_set(struct g1 *out, struct g1 *in) {
	curvepoint_fp_set(out->p, in->p);
}

void g1_set_x(struct g1 *a, const double *words) {
	memcpy(&a->p->m_x[0].v[0], words, sizeof(double) * 12);
}

void g1_set_y(struct g1 *a, const double *words) {
	memcpy(&a->p->m_y[0].v[0], words, sizeof(double) * 12);
}

void g1_init_zt(struct g1 *a) {
	fpe_setone(a->p->m_z);
	fpe_setone(a->p->m_t);
}

void g1_dump(struct g1 *a) {
	curvepoint_fp_print(stdout, a->p);
	printf("\n");
}

void g1_add(struct g1 *out, struct g1 *a, struct g1 *b) {
	curvepoint_fp_makeaffine(b->p);
	curvepoint_fp_mixadd(out->p, a->p, b->p);
}

void g1_make_affine(struct g1 *out) {
	curvepoint_fp_makeaffine(out->p);
}

double* g1_x(struct g1 *in) {
	return in->p[0].m_x[0].v;
}

double* g1_y(struct g1 *in) {
	return in->p[0].m_y[0].v;
}

void g1_neg(struct g1 *out, struct g1 *in) {
	curvepoint_fp_neg(out->p, in->p);
}

void g1_scalar_mult(struct g1 *out, struct g1 *base, unsigned long long *words, unsigned num_bits) {
	curvepoint_fp_mul(out->p, base->p, words, num_bits);
}


struct g2 {
	twistpoint_fp2_t p;
};

void g2_set_gen(struct g2 *a) {
	twistpoint_fp2_set(a->p, bn_twistgen);
}

void g2_set(struct g2 *out, struct g2 *in) {
	twistpoint_fp2_set(out->p, in->p);
}

void g2_double(struct g2 *a) {
	twistpoint_fp2_double(a->p, a->p);
}

void g2_set_x(struct g2 *a, const double *words) {
	memcpy(&a->p->m_x[0].v[0], words, sizeof(double) * 24);
}

void g2_set_y(struct g2 *a, const double *words) {
	memcpy(&a->p->m_y[0].v[0], words, sizeof(double) * 24);
}

void g2_init_zt(struct g2 *a) {
	fp2e_setone(a->p->m_z);
	fp2e_setone(a->p->m_t);
}

void g2_add(struct g2 *out, struct g2 *a, struct g2 *b) {
	twistpoint_fp2_makeaffine(b->p);
	twistpoint_fp2_mixadd(out->p, a->p, b->p);
}

void g2_make_affine(struct g2 *out) {
	twistpoint_fp2_makeaffine(out->p);
}

double* g2_x(struct g2 *in) {
	return in->p[0].m_x[0].v;
}

double* g2_y(struct g2 *in) {
	return in->p[0].m_y[0].v;
}

void g2_neg(struct g2 *out, struct g2 *in) {
	twistpoint_fp2_neg(out->p, in->p);
}

void g2_scalar_mult(struct g2 *out, struct g2 *base, unsigned long long *words, unsigned num_bits) {
	twistpoint_fp2_mul(out->p, base->p, words, num_bits);
}


struct gt {
	fp12e_t p;
};

void pair(struct gt *out, struct g1 *a, struct g2 *b) {
	g1_make_affine(a);
	g2_make_affine(b);
	optate(out->p, b->p, a->p);
}

void gt_set(struct gt *out, struct gt *in) {
	fp12e_set(out->p, in->p);
}

void gt_mul(struct gt *out, struct gt *a, struct gt *b) {
	fp12e_mul(out->p, a->p, b->p);
}

void gt_dump(struct gt *in) {
	fp12e_print(stdout, in->p);
	printf("\n");
}

double* gt_aa(struct gt *in) {
	return in->p[0].m_a[0].m_a[0].v;
}

double* gt_ab(struct gt *in) {
	return in->p[0].m_a[0].m_b[0].v;
}

double* gt_ac(struct gt *in) {
	return in->p[0].m_a[0].m_c[0].v;
}

double* gt_ba(struct gt *in) {
	return in->p[0].m_b[0].m_a[0].v;
}

double* gt_bb(struct gt *in) {
	return in->p[0].m_b[0].m_b[0].v;
}

double* gt_bc(struct gt *in) {
	return in->p[0].m_b[0].m_c[0].v;
}

void gt_neg(struct gt *out, struct gt *in) {
	fp12e_invert(out->p, in->p);
}

void gt_scalar_mult(struct gt *out, struct gt *base, unsigned long long *words, unsigned num_bits) {
	fp12e_pow(out->p, base->p, words, num_bits);
}

void gt_set_aa(struct gt *a, const double *words) {
	memcpy(&a->p->m_a[0].m_a[0], words, sizeof(double) * 24);
}

void gt_set_ab(struct gt *a, const double *words) {
	memcpy(&a->p->m_a[0].m_b[0], words, sizeof(double) * 24);
}

void gt_set_ac(struct gt *a, const double *words) {
	memcpy(&a->p->m_a[0].m_c[0], words, sizeof(double) * 24);
}

void gt_set_ba(struct gt *a, const double *words) {
	memcpy(&a->p->m_b[0].m_a[0], words, sizeof(double) * 24);
}

void gt_set_bb(struct gt *a, const double *words) {
	memcpy(&a->p->m_b[0].m_b[0], words, sizeof(double) * 24);
}

void gt_set_bc(struct gt *a, const double *words) {
	memcpy(&a->p->m_b[0].m_c[0], words, sizeof(double) * 24);
}

*/
import "C"

var v = new(big.Int).SetInt64(1868033)

func bigFromBase10(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 10)
	return n
}

// p is a prime over which we form a basic field: 36u⁴+36u³+24u³+6u+1.
var p = bigFromBase10("65000549695646603732796438742359905742825358107623003571877145026864184071783")

// Order is the number of elements in both G₁ and G₂: 36u⁴+36u³+18u³+6u+1.
var Order = bigFromBase10("65000549695646603732796438742359905742570406053903786389881062969044166799969")

type convertContext struct {
	vPower     *big.Int
	tmp        *big.Int
	acc        *big.Int
	doubles    [12]C.double
	doublesFP2 [24]C.double
}

func newConvertContext() *convertContext {
	return &convertContext{
		vPower: new(big.Int),
		tmp:    new(big.Int),
		acc:    new(big.Int),
	}
}

// doublesToInt sets out to a value decoded from 12 doubles in dclxvi's format.
// dclxvi stores values as described in [1], section 4.1.
func (c *convertContext) doublesToInt(out *big.Int, limbsIn *C.double) *big.Int {
	limbs := (*[12]C.double)(unsafe.Pointer(limbsIn))
	out.SetInt64(int64(limbs[0]))

	c.vPower.Set(v)
	c.tmp.SetInt64(int64(limbs[1]) * 6)
	c.tmp.Mul(c.tmp, c.vPower)
	out.Add(out, c.tmp)

	i := 2
	for factor := int64(6); factor <= 36; factor *= 6 {
		for j := 0; j < 5; j++ {
			c.vPower.Mul(c.vPower, v)
			c.tmp.SetInt64(int64(limbs[i]) * factor)
			c.tmp.Mul(c.tmp, c.vPower)
			out.Add(out, c.tmp)
			i++
		}
	}

	out.Mod(out, p)

	return out
}

// doublesFP2ToInt set out to a value decoded from 24 doubles in dclxvi's F(p²)
// format. dclxvi stores these values as pairs of the scalars where those
// scalars are in the form described in [1], section 4.1. The words of the two
// values are interleaved and phase (which must be either 0 or 1) determines
// which of the two values is decoded.
func (c *convertContext) doublesFP2ToInt(out *big.Int, limbsIn *C.double, phase int) *big.Int {
	limbs2 := (*[24]C.double)(unsafe.Pointer(limbsIn))
	var limbs [12]C.double

	for i := 0; i < 12; i++ {
		limbs[i] = limbs2[2*i+phase]
	}
	return c.doublesToInt(out, &limbs[0])
}

const numBytes = 32

var bigSix = big.NewInt(6)

func (c *convertContext) doublesToBytes(out []byte, v *C.double) {
	c.doublesToInt(c.acc, v)
	bytes := c.acc.Bytes()
	copy(out[numBytes-len(bytes):], bytes)
}

func (c *convertContext) doublesFP2ToBytes(out []byte, v2In *C.double) {
	c.doublesFP2ToInt(c.acc, v2In, 1)
	bytes := c.acc.Bytes()
	copy(out[numBytes-len(bytes):], bytes)

	c.doublesFP2ToInt(c.acc, v2In, 0)
	bytes = c.acc.Bytes()
	copy(out[numBytes*2-len(bytes):], bytes)
}

// bytesToDoubles converts a binary, big-endian number into 12 doubles that are
// in dclxvi's scalar format.
func (c *convertContext) bytesToDoubles(in []byte) {
	c.acc.SetBytes(in)

	c.vPower.Mul(bigSix, v)
	c.acc.DivMod(c.acc, c.vPower, c.tmp)
	c.doubles[0] = C.double(c.tmp.Int64())

	for i := 1; i < 6; i++ {
		c.acc.DivMod(c.acc, v, c.tmp)
		c.doubles[i] = C.double(c.tmp.Int64())
	}
	c.acc.DivMod(c.acc, c.vPower, c.tmp)
	c.doubles[6] = C.double(c.tmp.Int64())
	for i := 7; i < 11; i++ {
		c.acc.DivMod(c.acc, v, c.tmp)
		c.doubles[i] = C.double(c.tmp.Int64())
	}
	c.doubles[11] = C.double(c.acc.Int64())
}

// bytesToDoublesFP2 converts a pair of binary, big-endian values into 24
// doubles that are in dclxvi's F(p²) format.
func (c *convertContext) bytesToDoublesFP2(in []byte) {
	c.bytesToDoubles(in[:numBytes])
	for i := 0; i < 12; i++ {
		c.doublesFP2[2*i+1] = c.doubles[i]
	}
	c.bytesToDoubles(in[numBytes:])
	for i := 0; i < 12; i++ {
		c.doublesFP2[2*i] = c.doubles[i]
	}
}

func (c *convertContext) setG1X(e *G1) {
	C.g1_set_x(&e.p, &c.doubles[0])
}

func (c *convertContext) setG1Y(e *G1) {
	C.g1_set_y(&e.p, &c.doubles[0])
}

func (c *convertContext) setG2X(e *G2) {
	C.g2_set_x(&e.p, &c.doublesFP2[0])
}

func (c *convertContext) setG2Y(e *G2) {
	C.g2_set_y(&e.p, &c.doublesFP2[0])
}

func (c *convertContext) setGTAA(e *GT) {
	C.gt_set_aa(&e.p, &c.doublesFP2[0])
}

func (c *convertContext) setGTAB(e *GT) {
	C.gt_set_ab(&e.p, &c.doublesFP2[0])
}

func (c *convertContext) setGTAC(e *GT) {
	C.gt_set_ac(&e.p, &c.doublesFP2[0])
}

func (c *convertContext) setGTBA(e *GT) {
	C.gt_set_ba(&e.p, &c.doublesFP2[0])
}

func (c *convertContext) setGTBB(e *GT) {
	C.gt_set_bb(&e.p, &c.doublesFP2[0])
}

func (c *convertContext) setGTBC(e *GT) {
	C.gt_set_bc(&e.p, &c.doublesFP2[0])
}

type G1 struct {
	p C.struct_g1
}

func (e *G1) Add(a, b *G1) *G1 {
	C.g1_add(&e.p, &a.p, &b.p)
	return e
}

func (e *G1) Marshal() []byte {
	out := make([]byte, numBytes*2)
	C.g1_make_affine(&e.p)

	c := newConvertContext()
	c.doublesToBytes(out, C.g1_x(&e.p))
	c.doublesToBytes(out[numBytes:], C.g1_y(&e.p))

	return out
}

func (e *G1) String() string {
	C.g1_make_affine(&e.p)
	c := newConvertContext()
	x := c.doublesToInt(new(big.Int), C.g1_x(&e.p))
	y := c.doublesToInt(new(big.Int), C.g1_y(&e.p))
	return "bn256.G1(" + x.String() + ", " + y.String() + ")"
}

func (e *G1) Neg(a *G1) {
	C.g1_neg(&e.p, &a.p)
}

var baseG1 *G1

func init() {
	baseG1 = new(G1)
	C.g1_set_gen(&baseG1.p)
}

// powerToWords converts a exponent to a series of 64-bit words in
// little-endian order and also returns the bit-length of the exponent.
func powerToWords(kIn *big.Int) ([]uint64, int) {
	k := new(big.Int)
	if kIn.Sign() < 0 || kIn.Cmp(Order) >= 0 {
		k.Mod(kIn, Order)
	} else {
		k.Set(kIn)
	}
	if k.Sign() == 0 {
		return nil, 0
	}
	// This assumes that unsigned long long, in C land, is 64-bits.
	bitLen := k.BitLen()
	numWords := (bitLen + 63) / 64
	words := make([]uint64, numWords)
	for i := range words {
		words[i] = k.Uint64()
		k.Rsh(k, 64)
	}

	return words, bitLen
}

func (e *G1) ScalarMult(base *G1, k *big.Int) *G1 {
	words, bitLen := powerToWords(k)
	if bitLen == 0 {
		C.g1_set(&e.p, &base.p)
	} else {
		C.g1_make_affine(&base.p)
		C.g1_scalar_mult(&e.p, &base.p, (*C.ulonglong)(unsafe.Pointer(&words[0])), C.unsigned(bitLen))
	}
	return e
}

func (e *G1) ScalarBaseMult(k *big.Int) *G1 {
	return e.ScalarMult(baseG1, k)
}

func (e *G1) Unmarshal(m []byte) (*G1, bool) {
	if len(m) != numBytes*2 {
		return nil, false
	}

	c := newConvertContext()
	c.bytesToDoubles(m[:numBytes])
	c.setG1X(e)
	c.bytesToDoubles(m[numBytes:])
	c.setG1Y(e)
	C.g1_init_zt(&e.p)

	return e, true
}

type G2 struct {
	p C.struct_g2
}

func (e *G2) Add(a, b *G2) *G2 {
	C.g2_add(&e.p, &a.p, &b.p)
	return e
}

func (e *G2) Marshal() []byte {
	out := make([]byte, numBytes*4)
	C.g2_make_affine(&e.p)

	c := newConvertContext()
	c.doublesFP2ToBytes(out, C.g2_x(&e.p))
	c.doublesFP2ToBytes(out[2*numBytes:], C.g2_y(&e.p))

	return out
}

func (e *G2) String() string {
	C.g2_make_affine(&e.p)
	c := newConvertContext()
	xa := c.doublesFP2ToInt(new(big.Int), C.g2_x(&e.p), 1)
	xb := c.doublesFP2ToInt(new(big.Int), C.g2_x(&e.p), 0)
	ya := c.doublesFP2ToInt(new(big.Int), C.g2_y(&e.p), 1)
	yb := c.doublesFP2ToInt(new(big.Int), C.g2_y(&e.p), 0)
	return "bn256.G2((" + xa.String() + ", " + xb.String() + "), (" + ya.String() + ", " + yb.String() + "))"
}

func (e *G2) Neg(a *G2) {
	C.g2_neg(&e.p, &a.p)
}

var baseG2 *G2

func init() {
	baseG2 = new(G2)
	C.g2_set_gen(&baseG2.p)
}

func (e *G2) ScalarMult(base *G2, k *big.Int) *G2 {
	words, bitLen := powerToWords(k)
	if bitLen == 0 {
		C.g2_set(&e.p, &base.p)
	} else {
		C.g2_make_affine(&base.p)
		C.g2_scalar_mult(&e.p, &base.p, (*C.ulonglong)(unsafe.Pointer(&words[0])), C.unsigned(bitLen))
	}
	return e
}

func (e *G2) ScalarBaseMult(k *big.Int) *G2 {
	return e.ScalarMult(baseG2, k)
}

func (e *G2) Unmarshal(m []byte) (*G2, bool) {
	if len(m) != numBytes*4 {
		return nil, false
	}

	c := newConvertContext()
	c.bytesToDoublesFP2(m[:numBytes*2])
	c.setG2X(e)
	c.bytesToDoublesFP2(m[numBytes*2:])
	c.setG2Y(e)
	C.g2_init_zt(&e.p)

	return e, true
}

type GT struct {
	p C.struct_gt
}

func Pair(g1 *G1, g2 *G2) *GT {
	ret := new(GT)
	C.pair(&ret.p, &g1.p, &g2.p)
	return ret
}

func (e *GT) Add(a, b *GT) *GT {
	C.gt_mul(&e.p, &a.p, &b.p)
	return e
}

func (e *GT) Marshal() []byte {
	out := make([]byte, numBytes*12)

	c := newConvertContext()
	c.doublesFP2ToBytes(out[0*numBytes:], C.gt_aa(&e.p))
	c.doublesFP2ToBytes(out[2*numBytes:], C.gt_ab(&e.p))
	c.doublesFP2ToBytes(out[4*numBytes:], C.gt_ac(&e.p))
	c.doublesFP2ToBytes(out[6*numBytes:], C.gt_ba(&e.p))
	c.doublesFP2ToBytes(out[8*numBytes:], C.gt_bb(&e.p))
	c.doublesFP2ToBytes(out[10*numBytes:], C.gt_bc(&e.p))

	return out
}

func (e *GT) String() string {
	c := newConvertContext()
	a := c.doublesFP2ToInt(new(big.Int), C.gt_aa(&e.p), 1).String()
	b := c.doublesFP2ToInt(new(big.Int), C.gt_aa(&e.p), 0).String()
	cc := c.doublesFP2ToInt(new(big.Int), C.gt_ab(&e.p), 1).String()
	d := c.doublesFP2ToInt(new(big.Int), C.gt_ab(&e.p), 0).String()
	ee := c.doublesFP2ToInt(new(big.Int), C.gt_ac(&e.p), 1).String()
	f := c.doublesFP2ToInt(new(big.Int), C.gt_ac(&e.p), 0).String()
	g := c.doublesFP2ToInt(new(big.Int), C.gt_ba(&e.p), 1).String()
	h := c.doublesFP2ToInt(new(big.Int), C.gt_ba(&e.p), 0).String()
	i := c.doublesFP2ToInt(new(big.Int), C.gt_bb(&e.p), 1).String()
	j := c.doublesFP2ToInt(new(big.Int), C.gt_bb(&e.p), 0).String()
	k := c.doublesFP2ToInt(new(big.Int), C.gt_bc(&e.p), 1).String()
	l := c.doublesFP2ToInt(new(big.Int), C.gt_bc(&e.p), 0).String()

	return "GF12(" + strings.Join([]string{a, b, cc, d, ee, f, g, h, i, j, k, l}, ",") + ")"
}

func (e *GT) Neg(a *GT) *GT {
	C.gt_neg(&e.p, &a.p)
	return e
}

func (e *GT) ScalarMult(base *GT, k *big.Int) *GT {
	words, bitLen := powerToWords(k)
	if bitLen == 0 {
		C.gt_set(&e.p, &base.p)
	} else {
		C.gt_scalar_mult(&e.p, &base.p, (*C.ulonglong)(unsafe.Pointer(&words[0])), C.unsigned(bitLen))
	}
	return e
}

func (e *GT) Unmarshal(m []byte) (*GT, bool) {
	if len(m) != numBytes*12 {
		return nil, false
	}

	c := newConvertContext()
	c.bytesToDoublesFP2(m[0*numBytes : 2*numBytes])
	c.setGTAA(e)
	c.bytesToDoublesFP2(m[2*numBytes : 4*numBytes])
	c.setGTAB(e)
	c.bytesToDoublesFP2(m[4*numBytes : 6*numBytes])
	c.setGTAC(e)
	c.bytesToDoublesFP2(m[6*numBytes : 8*numBytes])
	c.setGTBA(e)
	c.bytesToDoublesFP2(m[8*numBytes : 10*numBytes])
	c.setGTBB(e)
	c.bytesToDoublesFP2(m[10*numBytes : 12*numBytes])
	c.setGTBC(e)

	return e, true
}

// RandomG1 returns x and g₁ˣ where x is a random, non-zero number read from r.
func RandomG1(r io.Reader) (*big.Int, *G1, error) {
	var k *big.Int
	var err error

	for {
		k, err = rand.Int(r, Order)
		if err != nil {
			return nil, nil, err
		}
		if k.Sign() > 0 {
			break
		}
	}

	return k, new(G1).ScalarBaseMult(k), nil
}

// RandomG2 returns x and g₂ˣ where x is a random, non-zero number read from r.
func RandomG2(r io.Reader) (*big.Int, *G2, error) {
	var k *big.Int
	var err error

	for {
		k, err = rand.Int(r, Order)
		if err != nil {
			return nil, nil, err
		}
		if k.Sign() > 0 {
			break
		}
	}

	return k, new(G2).ScalarBaseMult(k), nil
}
