package sw_bls12381

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
)

type G2 struct {
	*fields_bls12381.Ext2
	u1, w *emulated.Element[emulated.BLS12381Fp]
	v     *fields_bls12381.E2
}

type G2Affine struct {
	X, Y fields_bls12381.E2
}

func NewG2(api frontend.API) *G2 {
	w := emulated.ValueOf[emulated.BLS12381Fp]("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436")
	u1 := emulated.ValueOf[emulated.BLS12381Fp]("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437")
	v := fields_bls12381.E2{
		A0: emulated.ValueOf[emulated.BLS12381Fp]("2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530"),
		A1: emulated.ValueOf[emulated.BLS12381Fp]("1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257"),
	}
	return &G2{
		Ext2: fields_bls12381.NewExt2(api),
		w:    &w,
		u1:   &u1,
		v:    &v,
	}
}

func NewG2Affine(v bls12381.G2Affine) G2Affine {
	return G2Affine{
		X: fields_bls12381.E2{
			A0: emulated.ValueOf[emulated.BLS12381Fp](v.X.A0),
			A1: emulated.ValueOf[emulated.BLS12381Fp](v.X.A1),
		},
		Y: fields_bls12381.E2{
			A0: emulated.ValueOf[emulated.BLS12381Fp](v.Y.A0),
			A1: emulated.ValueOf[emulated.BLS12381Fp](v.Y.A1),
		},
	}
}

func (g2 *G2) psi(q *G2Affine) *G2Affine {
	x := g2.Ext2.MulByElement(&q.X, g2.u1)
	y := g2.Ext2.Conjugate(&q.Y)
	y = g2.Ext2.Mul(y, g2.v)

	return &G2Affine{
		X: fields_bls12381.E2{A0: x.A1, A1: x.A0},
		Y: *y,
	}
}

func (g2 *G2) scalarMulBySeed(q *G2Affine) *G2Affine {

	z := g2.triple(q)
	z = g2.double(z)
	z = g2.doubleAndAdd(z, q)
	z = g2.doubleN(z, 2)
	z = g2.doubleAndAdd(z, q)
	z = g2.doubleN(z, 8)
	z = g2.doubleAndAdd(z, q)
	z = g2.doubleN(z, 31)
	z = g2.doubleAndAdd(z, q)
	z = g2.doubleN(z, 16)

	return g2.neg(z)
}

func (g2 G2) add(p, q *G2Affine) *G2Affine {
	// compute λ = (q.y-p.y)/(q.x-p.x)
	qypy := g2.Ext2.Sub(&q.Y, &p.Y)
	qxpx := g2.Ext2.Sub(&q.X, &p.X)
	λ := g2.Ext2.DivUnchecked(qypy, qxpx)

	// xr = λ²-p.x-q.x
	λλ := g2.Ext2.Square(λ)
	qxpx = g2.Ext2.Add(&p.X, &q.X)
	xr := g2.Ext2.Sub(λλ, qxpx)

	// p.y = λ(p.x-r.x) - p.y
	pxrx := g2.Ext2.Sub(&p.X, xr)
	λpxrx := g2.Ext2.Mul(λ, pxrx)
	yr := g2.Ext2.Sub(λpxrx, &p.Y)

	return &G2Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g2 G2) neg(p *G2Affine) *G2Affine {
	xr := &p.X
	yr := g2.Ext2.Neg(&p.Y)
	return &G2Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g2 G2) sub(p, q *G2Affine) *G2Affine {
	qNeg := g2.neg(q)
	return g2.add(p, qNeg)
}

func (g2 *G2) double(p *G2Affine) *G2Affine {
	// compute λ = (3p.x²)/2*p.y
	xx3a := g2.Square(&p.X)
	xx3a = g2.MulByConstElement(xx3a, big.NewInt(3))
	y2 := g2.Double(&p.Y)
	λ := g2.DivUnchecked(xx3a, y2)

	// xr = λ²-2p.x
	x2 := g2.Double(&p.X)
	λλ := g2.Square(λ)
	xr := g2.Sub(λλ, x2)

	// yr = λ(p-xr) - p.y
	pxrx := g2.Sub(&p.X, xr)
	λpxrx := g2.Mul(λ, pxrx)
	yr := g2.Sub(λpxrx, &p.Y)

	return &G2Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g2 *G2) doubleN(p *G2Affine, n int) *G2Affine {
	pn := p
	for s := 0; s < n; s++ {
		pn = g2.double(pn)
	}
	return pn
}

func (g2 G2) triple(p *G2Affine) *G2Affine {

	// compute λ1 = (3p.x²)/2p.y
	xx := g2.Square(&p.X)
	xx = g2.MulByConstElement(xx, big.NewInt(3))
	y2 := g2.Double(&p.Y)
	λ1 := g2.DivUnchecked(xx, y2)

	// xr = λ1²-2p.x
	x2 := g2.MulByConstElement(&p.X, big.NewInt(2))
	λ1λ1 := g2.Square(λ1)
	x2 = g2.Sub(λ1λ1, x2)

	// ommit y2 computation, and
	// compute λ2 = 2p.y/(x2 − p.x) − λ1.
	x1x2 := g2.Sub(&p.X, x2)
	λ2 := g2.DivUnchecked(y2, x1x2)
	λ2 = g2.Sub(λ2, λ1)

	// xr = λ²-p.x-x2
	λ2λ2 := g2.Square(λ2)
	qxrx := g2.Add(x2, &p.X)
	xr := g2.Sub(λ2λ2, qxrx)

	// yr = λ(p.x-xr) - p.y
	pxrx := g2.Sub(&p.X, xr)
	λ2pxrx := g2.Mul(λ2, pxrx)
	yr := g2.Sub(λ2pxrx, &p.Y)

	return &G2Affine{
		X: *xr,
		Y: *yr,
	}
}

func (g2 G2) doubleAndAdd(p, q *G2Affine) *G2Affine {

	// compute λ1 = (q.y-p.y)/(q.x-p.x)
	yqyp := g2.Ext2.Sub(&q.Y, &p.Y)
	xqxp := g2.Ext2.Sub(&q.X, &p.X)
	λ1 := g2.Ext2.DivUnchecked(yqyp, xqxp)

	// compute x2 = λ1²-p.x-q.x
	λ1λ1 := g2.Ext2.Square(λ1)
	xqxp = g2.Ext2.Add(&p.X, &q.X)
	x2 := g2.Ext2.Sub(λ1λ1, xqxp)

	// ommit y2 computation
	// compute λ2 = -λ1-2*p.y/(x2-p.x)
	ypyp := g2.Ext2.Add(&p.Y, &p.Y)
	x2xp := g2.Ext2.Sub(x2, &p.X)
	λ2 := g2.Ext2.DivUnchecked(ypyp, x2xp)
	λ2 = g2.Ext2.Add(λ1, λ2)
	λ2 = g2.Ext2.Neg(λ2)

	// compute x3 =λ2²-p.x-x3
	λ2λ2 := g2.Ext2.Square(λ2)
	x3 := g2.Ext2.Sub(λ2λ2, &p.X)
	x3 = g2.Ext2.Sub(x3, x2)

	// compute y3 = λ2*(p.x - x3)-p.y
	y3 := g2.Ext2.Sub(&p.X, x3)
	y3 = g2.Ext2.Mul(λ2, y3)
	y3 = g2.Ext2.Sub(y3, &p.Y)

	return &G2Affine{
		X: *x3,
		Y: *y3,
	}
}

// AssertIsEqual asserts that p and q are the same point.
func (g2 *G2) AssertIsEqual(p, q *G2Affine) {
	g2.Ext2.AssertIsEqual(&p.X, &q.X)
	g2.Ext2.AssertIsEqual(&p.Y, &q.Y)
}
