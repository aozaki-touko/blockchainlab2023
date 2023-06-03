package main

import (
	"bytes"
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

type assistStruct struct {
	Version       int64
	PrevBlockHash [32]byte
	MerkleRoot    [32]byte
	Timestamp     int64
	Bits          int64
	Nonce         int64
}

// NewProofOfWork builds and returns a ProofOfWork
func NewProofOfWork(b *Block) *ProofOfWork {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-targetBits))

	pow := &ProofOfWork{b, target}

	return pow
}

// serilizehead
func (pow *ProofOfWork) makeHeader(nonce int64) []byte {
	prevHash := pow.block.GetPrevhash()
	mkHash := pow.block.Header.MerkleRoot
	temp := bytes.Join([][]byte{IntToHex(pow.block.Header.Version), prevHash[:], mkHash[:], IntToHex(pow.block.Header.Timestamp), IntToHex(pow.block.Header.Bits), IntToHex(nonce)}, []byte{})
	return temp
}

// Run performs a proof-of-work
// implement
func (pow *ProofOfWork) Run() (int64, []byte) {
	nonce := int64(0)
	for nonce < int64(maxNonce) {
		headerData := pow.makeHeader(nonce)
		hashHeader := sha256.Sum256(headerData)
		hashedVal := new(big.Int).SetBytes(hashHeader[:])
		if hashedVal.Cmp(pow.target) == -1 {
			pow.block.Header.Nonce = nonce
			break
		} else {
			nonce++
		}
	}
	return nonce, pow.makeHeader(nonce)
}

// Validate validates block's PoW
// implement
func (pow *ProofOfWork) Validate() bool {
	temp := pow.makeHeader(pow.block.Header.Nonce)

	//prevHash := pow.block.GetPrevhash()
	//res = append(res, prevHash[:]...)
	hashedSer := sha256.Sum256(temp)
	hashedVal := new(big.Int).SetBytes(hashedSer[:])
	if pow.target.Cmp(hashedVal) == 1 {
		return true
	}
	return false
}
