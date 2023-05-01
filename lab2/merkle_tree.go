package main

import (
	"bytes"
	"crypto/sha256"
	"golang.org/x/crypto/openpgp/errors"
)

// MerkleTree represent a Merkle tree
type MerkleTree struct {
	RootNode *MerkleNode
	Leaf     [][]byte
}

// MerkleNode represent a Merkle tree node
type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Data  []byte
}

// NewMerkleTree creates a new Merkle tree from a sequence of data
// implement
func NewMerkleTree(data [][]byte) *MerkleTree {
	if len(data) == 0 {
		return nil
	}
	if len(data) == 1 {
		sigNode := NewMerkleNode(nil, nil, data[0])
		ret := new(MerkleTree)
		ret.Leaf = data
		ret.RootNode = sigNode
		return ret
	} else {
		var nodes []*MerkleNode
		for _, eachTrade := range data {
			//eachHash := sha256.Sum256(eachTrade)
			nodes = append(nodes, NewMerkleNode(nil, nil, eachTrade))
		}
		for len(nodes) > 1 {
			if len(nodes)%2 != 0 {
				nodes = append(nodes, nodes[len(nodes)-1])
			}
			var level []*MerkleNode
			for i := 0; i < len(nodes); i += 2 {
				level = append(level, NewMerkleNode(nodes[i], nodes[i+1], nil))
			}
			nodes = level
		}
		ret := new(MerkleTree)
		ret.RootNode = nodes[0]
		ret.Leaf = data
		return ret
	}

}

// NewMerkleNode creates a new Merkle tree node
// implement
func NewMerkleNode(left, right *MerkleNode, data []byte) *MerkleNode {
	ret := new(MerkleNode)
	if left == nil && right == nil {
		shaVal := sha256.Sum256(data)
		ret.Data = shaVal[:]
		return ret
	} else {
		ret.Left = left
		ret.Right = right
		shaVal := sha256.Sum256(append(left.Data, right.Data...))
		ret.Data = shaVal[:]
		return ret
	}
}

func (t *MerkleTree) SPVproof(index int) ([][]byte, error) {
	if index > len(t.Leaf) {
		return nil, errors.ErrKeyIncorrect
	}
	var proofPath [][]byte
	var hashes [][]byte
	for _, leaf := range t.Leaf {
		hashVal := sha256.Sum256(leaf)
		hashes = append(hashes, hashVal[:])
	}
	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}

		if index%2 != 0 {
			proofPath = append(proofPath, hashes[index-1])
		} else {
			proofPath = append(proofPath, hashes[index+1])
		}
		index = index / 2
		var level [][]byte
		for i := 0; i < len(hashes); i += 2 {
			hashVal := sha256.Sum256(bytes.Join([][]byte{hashes[i], hashes[i+1]}, []byte{}))
			level = append(level, hashVal[:])
		}
		hashes = level

	}
	return proofPath, nil
}

func (t *MerkleTree) VerifyProof(index int, path [][]byte) (bool, error) {
	Leaf := sha256.Sum256(t.Leaf[index])
	hashLeaf := Leaf[:]
	for _, eachHash := range path {
		if index%2 == 0 {
			hashVal := sha256.Sum256(bytes.Join([][]byte{hashLeaf, eachHash}, []byte{}))
			hashLeaf = hashVal[:]
		} else {
			hashVal := sha256.Sum256(bytes.Join([][]byte{eachHash, hashLeaf}, []byte{}))
			hashLeaf = hashVal[:]
		}
		index = index / 2
	}
	for i := 0; i < 32; i++ {
		if t.RootNode.Data[i] != hashLeaf[i] {
			return false, nil
		}
	}
	return true, nil
}
