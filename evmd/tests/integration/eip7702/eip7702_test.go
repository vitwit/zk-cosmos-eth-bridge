package eip7702

import (
	"testing"

	"github.com/cosmos/evm/tests/integration/eip7702"
	"github.com/vitwit/zk-cosmos-eth-bridge/evmd/tests/integration"
)

func TestEIP7702IntegrationTestSuite(t *testing.T) {
	eip7702.TestEIP7702IntegrationTestSuite(t, integration.CreateEvmd)
}
