package ics20

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/cosmos/evm/tests/integration/precompiles/ics20"
	"github.com/vitwit/zk-cosmos-eth-bridge/evmd/tests/integration"
)

func TestICS20PrecompileTestSuite(t *testing.T) {
	s := ics20.NewPrecompileTestSuite(t, integration.SetupEvmd)
	suite.Run(t, s)
}

func TestICS20PrecompileIntegrationTestSuite(t *testing.T) {
	ics20.TestPrecompileIntegrationTestSuite(t, integration.SetupEvmd)
}
