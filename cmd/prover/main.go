package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/vitwit/zk-state-transition/testing/pkg/prover"
)

func main() {
	if len(os.Args) < 7 {
		fmt.Println("Usage: prover <rpc_url> <height> <tx_hash> <lock_id> <amount> <eth_dest>")
		return
	}

	rpcURL := os.Args[1]
	height, _ := strconv.ParseInt(os.Args[2], 10, 64)
	txHashStr := os.Args[3]
	lockID, _ := strconv.ParseUint(os.Args[4], 10, 64)
	amountStr := os.Args[5]
	ethDest := os.Args[6]

	p, err := prover.NewProver()
	if err != nil {
		log.Fatal(err)
	}

	proof, err := p.GenerateInclusionProof(rpcURL, height, txHashStr, lockID, amountStr, ethDest)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n--- Solidity Proof Data ---")
	fmt.Printf("A: [uint256(%s), uint256(%s)]\n", proof.A[0], proof.A[1])
	fmt.Printf("B: [[uint256(%s), uint256(%s)], [uint256(%s), uint256(%s)]]\n",
		proof.B[0][0], proof.B[0][1], proof.B[1][0], proof.B[1][1])
	fmt.Printf("C: [uint256(%s), uint256(%s)]\n", proof.C[0], proof.C[1])

	fmt.Print("Input: [")
	for i, input := range proof.Inputs {
		fmt.Printf("uint256(%s)", input)
		if i < len(proof.Inputs)-1 {
			fmt.Print(", ")
		}
	}
	fmt.Println("]")
	fmt.Println("---------------------------")

	fmt.Println("Success! ZK proof generated.")
}
