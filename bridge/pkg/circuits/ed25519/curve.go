package ed25519

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type Curve struct {
	api    frontend.API
	field  *emulated.Field[Ed25519Fp]
	params Ed25519Params
}

func NewCurve(api frontend.API) (*Curve, error) {
	f, err := emulated.NewField[Ed25519Fp](api)
	if err != nil {
		return nil, err
	}
	return &Curve{
		api:    api,
		field:  f,
		params: GetEd25519Params(),
	}, nil
}

func (c *Curve) AssertIsOnCurve(p Point) {
	// ax^2 + y^2 = 1 + dx^2y^2
	x2 := c.field.Mul(&p.X, &p.X)
	y2 := c.field.Mul(&p.Y, &p.Y)

	ax2 := c.field.Mul(x2, &c.params.A)
	lhs := c.field.Add(ax2, y2)

	dx2 := c.field.Mul(x2, &c.params.D)
	dx2y2 := c.field.Mul(dx2, y2)
	rhs := c.field.Add(dx2y2, c.field.One())

	c.field.AssertIsEqual(lhs, rhs)
}

func (c *Curve) Add(p1, p2 Point) Point {
	// x3 = (x1y2 + y1x2) / (1 + dx1x2y1y2)
	// y3 = (y1y2 - ax1x2) / (1 - dx1x2y1y2)

	x1y2 := c.field.Mul(&p1.X, &p2.Y)
	y1x2 := c.field.Mul(&p1.Y, &p2.X)
	y1y2 := c.field.Mul(&p1.Y, &p2.Y)
	x1x2 := c.field.Mul(&p1.X, &p2.X)

	dx1x2y1y2 := c.field.Mul(x1x2, y1y2)
	dx1x2y1y2 = c.field.Mul(dx1x2y1y2, &c.params.D)

	numX := c.field.Add(x1y2, y1x2)
	denX := c.field.Add(c.field.One(), dx1x2y1y2)
	resX := c.field.Div(numX, denX)

	ax1x2 := c.field.Mul(x1x2, &c.params.A)
	numY := c.field.Sub(y1y2, ax1x2)
	denY := c.field.Sub(c.field.One(), dx1x2y1y2)
	resY := c.field.Div(numY, denY)

	return Point{X: *resX, Y: *resY}
}

func (c *Curve) Double(p1 Point) Point {
	return c.Add(p1, p1)
}

func (c *Curve) ScalarMul(p1 Point, scalarBits []frontend.Variable) Point {
	res := Point{
		X: *c.field.Zero(),
		Y: *c.field.One(),
	}

	tmp := p1
	for i := 0; i < len(scalarBits); i++ {
		// addTmp = res + tmp
		addTmp := c.Add(res, tmp)

		// res = scalarBits[i] ? addTmp : res
		res.X = *c.field.Select(scalarBits[i], &addTmp.X, &res.X)
		res.Y = *c.field.Select(scalarBits[i], &addTmp.Y, &res.Y)

		tmp = c.Double(tmp)
	}

	return res
}

func (c *Curve) Neg(p1 Point) Point {
	return Point{
		X: *c.field.Neg(&p1.X),
		Y: p1.Y,
	}
}
