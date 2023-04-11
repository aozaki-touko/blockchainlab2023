package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/bits"
)

var (
	//8个初始哈希
	h0 = uint32(0x6a09e667)
	h1 = uint32(0xbb67ae85)
	h2 = uint32(0x3c6ef372)
	h3 = uint32(0xa54ff53a)
	h4 = uint32(0x510e527f)
	h5 = uint32(0x9b05688c)
	h6 = uint32(0x1f83d9ab)
	h7 = uint32(0x5be0cd19)

	//64个常量
	k = [64]uint32{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	}
)

func sha256impl(msg []byte) [32]byte {
	padding := append(msg, 0x80)
	emptyByte := new(byte)
	if len(padding)%64 < 56 {
		//mod 512 < 448
		for len(padding)%64 < 56 {
			padding = append(padding, *emptyByte)
		}
	} else {
		numOfByteToBeAdd := 64 + 56 - len(padding)
		for i := 0; i < numOfByteToBeAdd; i++ {
			padding = append(padding, *emptyByte)
		}
	}
	msgLen := make([]byte, 8)
	binary.BigEndian.PutUint64(msgLen, uint64(len(msg))*8)
	padding = append(padding, msgLen...)

	//分割成len(padding)/64 个 64字节的块
	message_blocks := [][]byte{}
	for i := 0; i < len(padding)/64; i++ {
		each_block := make([]byte, 64)
		copy(each_block, padding[i*64:i*64+64])
		message_blocks = append(message_blocks, each_block)
	}

	for _, block := range message_blocks {
		w := [64]uint32{}
		//分成16 个 32 位整数
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(block[i*4 : i*4+4])
		}

		for i := 16; i < 64; i++ {
			s0 := bits.RotateLeft32(w[i-15], -7) ^ bits.RotateLeft32(w[i-15], -18) ^ (w[i-15] >> 3)
			s1 := bits.RotateLeft32(w[i-2], -17) ^ bits.RotateLeft32(w[i-2], -19) ^ (w[i-2] >> 10)
			w[i] = s0 + s1 + w[i-16] + w[i-7]
		}

		//初始化哈希
		a := h0
		b := h1
		c := h2
		d := h3
		e := h4
		f := h5
		g := h6
		h := h7

		for i := 0; i < 64; i++ {
			s0 := bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)
			maj := (a & b) ^ (a & c) ^ (b & c)
			t2 := s0 + maj
			s1 := bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)
			ch := (e & f) ^ (^e & g)
			t1 := h + s1 + ch + k[i] + w[i]

			h = g
			g = f
			f = e
			e = d + t1
			d = c
			c = b
			b = a
			a = t1 + t2
		}

		h0 = h0 + a
		h1 = h1 + b
		h2 = h2 + c
		h3 = h3 + d
		h4 = h4 + e
		h5 = h5 + f
		h6 = h6 + g
		h7 = h7 + h
	}
	//转换为byte
	hash := []uint32{h0, h1, h2, h3, h4, h5, h6, h7}
	result := [32]byte{}
	for i, u := range hash {
		binary.BigEndian.PutUint32(result[i*4:i*4+4], u)
	}
	fmt.Printf("%x\n", result)
	fmt.Printf("%x\n", sha256.Sum256(msg))
	return result
}

func main() {
	test := []byte("hello")
	sha256impl(test)
}
//reference:
//https://zh.wikipedia.org/wiki/SHA-2
//
//
//