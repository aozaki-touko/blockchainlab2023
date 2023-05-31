package main

import (
	"crypto/sha256"
	"math"
	"math/big"
)

var (
	maxNonce = math.MaxInt64
)

const targetBits = 8

// ProofOfWork represents a proof-of-work
type ProofOfWork struct {
	block  *Block
	target *big.Int
}

// NewProofOfWork builds and returns a ProofOfWork
func NewProofOfWork(b *Block) *ProofOfWork {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-targetBits))

	pow := &ProofOfWork{b, target}

	return pow
}

// Run performs a proof-of-work
// implement
func (pow *ProofOfWork) Run() (int64, []byte) {
	nonce := int64(0)

	return nonce, nil
}

// Validate validates block's PoW
// implement
func (pow *ProofOfWork) Validate() bool {
	ser := pow.block.Serialize()
	//targetVal := new(big.Int).Exp(big.NewInt(int64(2)), big.NewInt(int64(256)-pow.target.Int64()), nil)
	hashedSer := sha256.Sum256(ser)
	hashedVal := new(big.Int).SetBytes(hashedSer[:])
	if pow.target.Cmp(hashedVal) == 1 {
		return true
	}
	return false
}
