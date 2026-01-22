package circuit

import (
	"github.com/consensys/gnark/frontend"
)

type CommitCircuit struct {
	PublicInput frontend.Variable `gnark:",public"`
	SecretInput frontend.Variable
}

func (c *CommitCircuit) Define(api frontend.API) error {
	// Commit to both public and secret inputs
	commitment, err := api.(frontend.Committer).Commit(c.PublicInput, c.SecretInput)
	if err != nil {
		return err
	}

	// Use the commitment in some way to ensure it's not optimized away
	api.AssertIsDifferent(commitment, 0)

	return nil
}
