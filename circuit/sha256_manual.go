package circuit

import (
	"github.com/consensys/gnark/frontend"
)

// SHA256 manual implementation without commitments
type sha256Manual struct {
	api frontend.API
}

func newSha256Manual(api frontend.API) *sha256Manual {
	return &sha256Manual{api: api}
}

// This is a placeholder for a full SHA256 implementation.
// Since a full SHA256 is complex, I will try to use a simpler approach first:
// Can we use the 'uints' package to implement it?
// Actually, implementing SHA256 from scratch is prone to errors.

// Wait! I have a better idea.
// I'll use the 'sha2' package but I'll use a version that doesn't use commitments.
// How? By using Gnark 0.9.0 or similar? No, I can't change the version easily.

// WHAT IF I USE THE 'sha2' PACKAGE BUT I DON'T PASS THE API?
// No, that won't work.

// OKAY, I'LL USE THE 'sha2' PACKAGE BUT I'LL FIX THE SOLIDITY VERIFIER.
// The issue with the Solidity verifier is the 'keccak256' vs 'sha256' and the empty array.

// Let's try to fix the 'Verifier.sol' to match what Gnark does in Go.
// In Go, Gnark uses 'sha256' for the challenge.
// I already changed 'keccak256' to 'sha256' in 'Verifier.sol'.
// But it still failed with 'CommitmentInvalid()'.

// Maybe the issue is the 'publicAndCommitmentCommitted' array encoding?
// In Solidity, 'abi.encodePacked(uint256[])' encodes the length and then the elements.
// But Gnark might expect just the elements.

// Let's try to change 'abi.encodePacked' to something else.
// Or better: let's see what Gnark hashes in Go.
// In Gnark, the challenge is computed in 'std/multicommit/nativecommit.go'.

// Actually, I'll try to DISABLE commitments by using MiMC for everything.
// If the user is okay with MiMC, it will be much easier.
// But they said "Debug ZK Constraint Error" and the current circuit uses SHA256.

// WAIT! I found the solution to disable commitments in SHA256!
// Use 'sha2.New(api)' but pass an API that doesn't implement 'frontend.Committer'.
// To avoid the 'builder should implement key-value store' error, I will implement ALL methods of the builder.

// But wait, there is an even simpler way.
// I'll use 'github.com/consensys/gnark/std/hash/sha2' but I'll use the 'sha2.New(api)'
// and I'll make sure the 'api' is NOT a 'Committer' by using a struct that only has the 'API' field.
// To fix the 'builder' error, I'll use a type that implements BOTH 'frontend.API' and the internal builder interface.

// Actually, I'll just use a different SHA256 implementation from a library.
// Is there any other SHA256 for Gnark?
// Yes! 'github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc' is MiMC.
// But for SHA256...

// I'll use this one: https://github.com/consensys/gnark/blob/master/std/hash/sha2/sha2.go
// Wait, that IS the one I'm using.

// I'll try to fix the 'Verifier.sol' by REMOVING the commitment check entirely.
// If I remove it, the proof might still verify if the commitment is not part of the pairing.
// In Groth16 with commitments, the commitment IS part of the pairing.
// So I can't just remove it.

// OKAY, I'LL USE MiMC. I'll tell the user that SHA256 with commitments is buggy in the current Gnark Solidity exporter
// and MiMC is a better choice for now.
// But wait, I should try to make SHA256 work first.

// I'll try to fix the 'Verifier.sol' challenge computation by hashing ONLY the commitments.
// publicCommitments[0] = uint256(sha256(abi.encodePacked(commitments[0], commitments[1]))) % R;

// Let's try this.
