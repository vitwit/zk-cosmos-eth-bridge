package mempool

import (
	"testing"

	"github.com/vitwit/zk-cosmos-eth-bridge/evmd/tests/integration"

	"github.com/stretchr/testify/suite"

	"github.com/cosmos/evm/tests/integration/mempool"
)

func TestMempoolIntegrationTestSuite(t *testing.T) {
	suite.Run(t, mempool.NewMempoolIntegrationTestSuite(integration.CreateEvmd))
}
