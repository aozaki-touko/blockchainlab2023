package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/btcsuite/btcutil/base58"

	"github.com/boltdb/bolt"
)

const dbFile = "blockchain.db"
const blocksBucket = "blocks"
const genesisCoinbaseData = "blockchainlab2023"

// Blockchain keeps a sequence of Blocks
type Blockchain struct {
	tip []byte
	db  *bolt.DB
}

// BlockchainIterator is used to iterate over blockchain blocks
type BlockchainIterator struct {
	currentHash []byte
	db          *bolt.DB
}

func (bc *Blockchain) FindTransaction(ID []byte) (*Transaction, error) {
	bci := bc.Iterator()

	for {
		block := bci.Next()

		for _, tx := range block.GetTransactions() {
			if bytes.Compare(tx.ID, ID) == 0 {
				return tx, nil
			}
		}

		if block.GetPrevhash() == [32]byte{} {
			break
		}
	}

	return nil, fmt.Errorf("Transaction is not found")
}

func (bc *Blockchain) SignTransaction(tx *Transaction, privKey ecdsa.PrivateKey) {
	prevTXs := make(map[string]*Transaction)

	for _, vin := range tx.Vin {
		prevTX, err := bc.FindTransaction(vin.Txid)
		if err != nil {
			log.Panic(err)
		}
		prevTXs[hex.EncodeToString(prevTX.ID)] = prevTX
	}

	tx.Sign(privKey, prevTXs)
}

// 判断交易是否合法
func (bc *Blockchain) VerifyTransaction(tx *Transaction) bool {
	if tx.IsCoinBase() {
		return true
	}

	prevTXs := make(map[string]*Transaction)

	for _, vin := range tx.Vin {
		prevTX, err := bc.FindTransaction(vin.Txid)
		if err != nil {
			log.Panic(err)
		}
		prevTXs[hex.EncodeToString(prevTX.ID)] = prevTX
	}

	return tx.Verify(prevTXs)
}

// AddBlock saves provided data as a block in the blockchain
// implement
// MineBlock mines a new block with the provided transactions
func (bc *Blockchain) MineBlock(transactions []*Transaction) *Block {
	var prevHash []byte
	for _, transaction := range transactions {
		if bc.VerifyTransaction(transaction) != true {
			log.Panic("error transaction")
		}
	}
	//now get prev hash
	db := bc.db
	err := db.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket([]byte(blocksBucket))
		prevHash = bk.Get([]byte("l"))
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	//now start mine
	var hashVal [32]byte
	copy(hashVal[:], prevHash)
	blk := NewBlock(transactions, hashVal)

	//now write back to db
	err = db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket([]byte(blocksBucket))
		err := bk.Put(blk.CalCulHash(), blk.Serialize())
		if err != nil {
			log.Panic(err)
		}
		err = bk.Put([]byte("l"), blk.CalCulHash())
		if err != nil {
			log.Panic(err)
		}
		bc.tip = blk.CalCulHash()
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	return blk
}

// Iterator ...
func (bc *Blockchain) Iterator() *BlockchainIterator {
	bci := &BlockchainIterator{bc.tip, bc.db}

	return bci
}

// Next returns next block starting from the tip
func (i *BlockchainIterator) Next() *Block {
	var block *Block

	err := i.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		encodedBlock := b.Get(i.currentHash)
		block = DeserializeBlock(encodedBlock)

		return nil
	})

	if err != nil {
		log.Panic(err)
	}
	hash := block.GetPrevhash()
	i.currentHash = hash[:]

	return block
}

// CreateBlockchain creates a new blockchain DB
func CreateBlockchain(address string) *Blockchain {
	if dbExists() {
		fmt.Println("Blockchain already exists.")
		os.Exit(1)
	}

	var tip []byte

	//addressBytes, err := hex.DecodeString(address)

	data, err := hex.DecodeString(address)
	if err != nil {
		log.Fatal(err)
	}

	pubKeyHash := base58.Decode(string(data))
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-4]
	coinbaseBytes := []byte(genesisCoinbaseData)

	cbtx := NewCoinbaseTx(pubKeyHash, coinbaseBytes)
	genesis := NewGenesisBlock(cbtx)

	db, err := bolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Panic(err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket([]byte(blocksBucket))
		if err != nil {
			log.Panic(err)
		}

		err = b.Put(genesis.CalCulHash(), genesis.Serialize())
		if err != nil {
			log.Panic(err)
		}

		err = b.Put([]byte("l"), genesis.CalCulHash())
		if err != nil {
			log.Panic(err)
		}
		tip = genesis.CalCulHash()

		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	bc := Blockchain{tip, db}

	return &bc
}

// NewBlockchain creates a new Blockchain with genesis Block
func NewBlockchain() *Blockchain {
	if dbExists() == false {
		fmt.Println("No existing blockchain found. Create one first.")
		os.Exit(1)
	}

	var tip []byte
	db, err := bolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Panic(err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		tip = b.Get([]byte("l"))

		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	bc := Blockchain{tip, db}

	return &bc
}

func (bc *Blockchain) FindUTXO() map[string]TXOutputs {
	utxos := make(map[string]TXOutputs)
	spentUTXO := make(map[string][]int)
	iter := bc.Iterator()
	for {
		block := iter.Next()
		for _, transaction := range block.GetTransactions() {
			txid := hex.EncodeToString(transaction.ID)
			//coinbase 没有vin
			if !transaction.IsCoinBase() {
				for _, input := range transaction.Vin {
					inId := hex.EncodeToString(input.Txid)
					spentUTXO[inId] = append(spentUTXO[inId], input.Vout)
				}
			}
			for idx, out := range transaction.Vout {
				found := false
				if spentUTXO[txid] != nil {
					for _, spentOut := range spentUTXO[txid] {
						if spentOut == idx {
							found = true
							break
						}
					}
				}
				if !found {
					outs := utxos[txid]
					outs.Outputs = append(outs.Outputs, out)
					utxos[txid] = outs
				}
			}

		}
		if block.GetPrevhash() == [32]byte{} {
			break
		}
	}
	return utxos
}

func (bc *Blockchain) Close() error {
	return bc.db.Close()
}

func dbExists() bool {
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		return false
	}

	return true
}
