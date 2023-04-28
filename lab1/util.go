package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"math/big"

)

var two = new(big.Int).SetInt64(2)

func newRand() (*big.Int, error) {
	pk, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return pk.D, nil
}

func checkBigIntSize(b *big.Int) error {
	// check b.Bytes()==32, as go returns big-endian representation of the
	// bigint, so if length is not 32 we have a smaller value than expected
	if len(b.Bytes()) != 32 { //nolint:gomnd
		return fmt.Errorf("invalid length, need 32 bytes")
	}
	return nil
}

func Multi(p *Point, msg *big.Int) *Point {
	x, y := s256.ScalarMult(p.X, p.Y, msg.Bytes())
	return &Point{
		X: x,
		Y: y,
	}
}

func Add(p *Point, q *Point) *Point {
	x, y := s256.Add(p.X, p.Y, q.X, q.Y)
	return &Point{
		X: x,
		Y: y,
	}
}

func Pow(s *big.Int, exp, N *big.Int) *big.Int {
	flagNum := new(big.Int).SetBytes(exp.Bytes())
	cur := new(big.Int).SetBytes(s.Bytes())
	res := new(big.Int).SetInt64(1)
	flag := new(big.Int).SetInt64(1)
	for flagNum.Sign() > 0 {
		tmp := new(big.Int).And(flagNum, flag)
		if tmp.Cmp(flag) == 0 {
			res.Mul(res, cur)
			res.Mod(res, N)
		}
		cur.Mul(cur, cur)
		cur.Mod(cur, N)
		flagNum.Rsh(flagNum, 1)
	}
	return res
}

func Inv(s *big.Int, N *big.Int) *big.Int {
	return Pow(s, new(big.Int).Sub(N, two), N)
}

