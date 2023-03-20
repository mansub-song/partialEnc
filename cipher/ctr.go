// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Counter (CTR) mode.

// CTR converts a block cipher into a stream cipher by
// repeatedly encrypting an incrementing counter and
// xoring the resulting stream of data with the input.

// See NIST SP 800-38A, pp 13-15

package cipher

import (
	"math/rand"

	"github.com/mansub1029/reapchain-ipfs/encrypt/bitmap"
	"github.com/mansub1029/reapchain-ipfs/encrypt/subtle"
)

type ctr struct {
	b       Block
	ctr     []byte
	out     []byte
	outUsed int
}

const streamBufferSize = 512
const EncryptionRatio = 8

// ctrAble is an interface implemented by ciphers that have a specific optimized
// implementation of CTR, like crypto/aes. NewCTR will check for this interface
// and return the specific Stream if found.
type ctrAble interface {
	NewCTR(iv []byte) *ctr
}

// NewCTR returns a Stream which encrypts/decrypts using the given Block in
// counter mode. The length of iv must be the same as the Block's block size.
func NewCTR(block Block, iv []byte) *ctr {
	if ctr, ok := block.(ctrAble); ok {
		return ctr.NewCTR(iv)
	}
	if len(iv) != block.BlockSize() {
		panic("cipher.NewCTR: IV length must equal block size")
	}
	bufSize := streamBufferSize
	if bufSize < block.BlockSize() {
		bufSize = block.BlockSize()
	}
	return &ctr{
		b:       block,
		ctr:     dup(iv),
		out:     make([]byte, 0, bufSize),
		outUsed: 0,
	}
}

func (x *ctr) refill() {
	remain := len(x.out) - x.outUsed
	copy(x.out, x.out[x.outUsed:])
	x.out = x.out[:cap(x.out)] //이때부터 len(x.out) = 512임
	bs := x.b.BlockSize()
	for remain <= len(x.out)-bs {
		x.b.Encrypt(x.out[remain:], x.ctr)
		remain += bs

		// Increment counter
		for i := len(x.ctr) - 1; i >= 0; i-- {
			x.ctr[i]++
			if x.ctr[i] != 0 {
				break
			}
		}
	}
	x.out = x.out[:remain]
	x.outUsed = 0
}

func (x *ctr) refill_partial(numEncRefill *int, bmap *bitmap.Bitmap, bmapOffset uint64) {
	remain := len(x.out) - x.outUsed
	copy(x.out, x.out[x.outUsed:])
	x.out = x.out[:cap(x.out)] //512bytes

	var bmapFlag bool
	if bmap.GetBit(bmapOffset) == 1 {
		*numEncRefill--
		bmapFlag = true
	}

	bs := x.b.BlockSize()
	for remain <= len(x.out)-bs {
		if *numEncRefill >= 0 && bmapFlag {
			x.b.Encrypt(x.out[remain:], x.ctr)
		}
		remain += bs

		// Increment counter
		for i := len(x.ctr) - 1; i >= 0; i-- {
			x.ctr[i]++
			if x.ctr[i] != 0 {
				break
			}
		}
	}
	x.out = x.out[:remain]
	x.outUsed = 0
}

func (x *ctr) XORKeyStream(dst, src, bmapByte []byte) []byte {
	// fmt.Println("len(dst):", len(dst), "len(src):", len(src))
	var bmap *bitmap.Bitmap
	var bmapOffset uint64 = 0

	numRefill := len(src) / x.b.BlockSize() / 32 //32는 refill 함수 한번당 32번의 ecnrypt를 수행하기 때문
	if (len(src) / x.b.BlockSize() % 32) != 0 {
		numRefill++
	}
	numEncRefill := numRefill / EncryptionRatio // 1:x 비율로 encryption

	//하나도 encrypt할것이 없으면 그냥 싹 다 하기
	if numEncRefill < 1 {
		numEncRefill = numRefill
	}

	bmap = createBitMap(numRefill, numEncRefill, bmapByte, src)

	// fmt.Println("createBitMap elapse:", elapse)
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	if subtle.InexactOverlap(dst[:len(src)], src) {
		panic("crypto/cipher: invalid buffer overlap")
	}

	for len(src) > 0 {
		if x.outUsed >= len(x.out)-x.b.BlockSize() {
			x.refill_partial(&numEncRefill, bmap, bmapOffset)
			bmapOffset++
		}
		n := xorBytes(dst, src, x.out[x.outUsed:])
		dst = dst[n:]
		src = src[n:]
		x.outUsed += n
	}

	// fmt.Println("refill elapse:", elapse1)

	if bmapByte == nil {
		return bmap.GetData()
	}
	return nil
}

// bitmap을 위한 xorkeystream
func (x *ctr) XORKeyStreamBitmap(dst, src []byte) {
	// fmt.Println("len(dst):", len(dst), "len(src):", len(src))
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	if subtle.InexactOverlap(dst[:len(src)], src) {
		panic("crypto/cipher: invalid buffer overlap")
	}
	for len(src) > 0 {
		if x.outUsed >= len(x.out)-x.b.BlockSize() {
			// fmt.Println("bitmap refill")
			x.refill()
		}
		n := xorBytes(dst, src, x.out[x.outUsed:])
		dst = dst[n:]
		src = src[n:]
		x.outUsed += n
	}

}

func createBitMap(numRefill, numEncRefill int, bmapByte, src []byte) *bitmap.Bitmap {
	// fmt.Println("numRefill:", numRefill)
	// fmt.Println("numEncRefill:", numEncRefill)
	bmap := bitmap.NewBitmapSize(numRefill)
	if bmapByte == nil { //encrypt
		///////////////////////////////////////////////

		// shaByte := sha256.Sum256(src)
		// var r = big.NewInt(0).SetBytes(shaByte[:]) // bytes to big Int
		// var shaInt uint64 = uint64(r.Int64())      // big Int to int
		// tmpShaInt := shaInt

		///////////////////////////////////////////////

		for i := 0; i < numEncRefill; {
			///////////////////////////////////////////////

			// if tmpShaInt > uint64(numRefill*2) {
			// 	tmpShaInt = tmpShaInt >> 1
			// } else { //전체 refill 횟수보다 2배보다 작으면 shaInt값이 너무 작다는 뜻이니까 채워준다 -> sha 함수는 output을 다음 sha함수의 input으로 사용해서 채운다.
			// 	// fmt.Println("refil!!")
			// 	shaByte = sha256.Sum256(shaByte[:])
			// 	r = big.NewInt(0).SetBytes(shaByte[:])
			// 	shaInt = uint64(r.Int64())
			// 	tmpShaInt = shaInt
			// }

			///////////////////////////////////////////////

			// offset := tmpShaInt % uint64(numRefill)

			offset := uint64(rand.Intn(numRefill))

			///////////////////////////////////////////////
			// if bmap.GetBit(offset) == 1 {
			// 	continue
			// }
			// fmt.Println("tmpShaInt:", tmpShaInt, "offset:", offset)
			///////////////////////////////////////////////

			bmap.SetBit(offset, 1)
			i++

		}
	} else { //decrypt
		// fmt.Printf("bmapByte:%#v\n", bmapByte)

		for index := 0; index < len(bmapByte); index++ {
			for pos := 0; pos < 8; pos++ { // 8 = 1byte
				bit := (bmapByte[index] >> pos) & 0x01
				if bit == 0x01 {
					offset := uint64(index*8 + pos)
					bmap.SetBit(offset, 1)
				}
			}
		}

	}
	// fmt.Println("bamp string:", bmap.String())
	return bmap
}
