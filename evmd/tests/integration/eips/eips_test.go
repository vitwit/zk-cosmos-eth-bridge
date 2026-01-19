package eips_test

import (
	"testing"

	"github.com/cosmos/evm/tests/integration/eips"
	"github.com/vitwit/zk-cosmos-eth-bridge/evmd/tests/integration"
	//nolint:revive // dot imports are fine for Ginkgo
	//nolint:revive // dot imports are fine for Ginkgo
)

func TestEIPs(t *testing.T) {
	eips.RunTests(t, integration.CreateEvmd)
}
