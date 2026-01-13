package bech32

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/cosmos/evm/tests/integration/precompiles/bech32"
	"github.com/vitwit/zk-cosmos-eth-bridge/evmd/tests/integration"
)

func TestBech32PrecompileTestSuite(t *testing.T) {
	s := bech32.NewPrecompileTestSuite(integration.CreateEvmd)
	suite.Run(t, s)
}
