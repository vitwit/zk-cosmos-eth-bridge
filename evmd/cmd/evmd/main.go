package main

import (
	"fmt"
	"os"

	svrcmd "github.com/cosmos/cosmos-sdk/server/cmd"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/evm/config"
	"github.com/vitwit/zk-cosmos-eth-bridge/evmd/cmd/evmd/cmd"
)

func main() {
	setupSDKConfig()

	rootCmd := cmd.NewRootCmd()
	if err := svrcmd.Execute(rootCmd, "evmd", config.MustGetDefaultNodeHome()); err != nil {
		fmt.Fprintln(rootCmd.OutOrStderr(), err)
		os.Exit(1)
	}
}

func setupSDKConfig() {
	cfg := sdk.GetConfig()
	config.SetBech32Prefixes(cfg)
	cfg.Seal()
}
