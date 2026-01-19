package staking

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/cosmos/evm/tests/integration/precompiles/staking"
	"github.com/vitwit/zk-cosmos-eth-bridge/evmd/tests/integration"
)

func TestStakingPrecompileTestSuite(t *testing.T) {
	s := staking.NewPrecompileTestSuite(integration.CreateEvmd)
	suite.Run(t, s)
}

func TestStakingPrecompileIntegrationTestSuite(t *testing.T) {
	staking.TestPrecompileIntegrationTestSuite(t, integration.CreateEvmd)
}
