package circuit

import (
	"github.com/consensys/gnark/frontend"
)

type BasicCircuit struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable
}

func (c *BasicCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, c.Y)
	return nil
}
