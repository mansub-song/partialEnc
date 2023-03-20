package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
	"math/big"
	"time"

	reapCipher "github.com/mansub1029/reapchain-ipfs/encrypt/cipher"
)

const (
	AES128_CTR = iota
	AES256_CTR
	headerLength = 10
)

var default_algorithm = AES256_CTR
var default_version = 1
var optFlag = true

func checkErr(err error) {
	if err != nil {
		fmt.Printf("Error is %+v\n", err)
		log.Fatal("ERROR:", err)
	}
}

func insert(array []byte, index int, element byte) []byte {
	result := append(array, element)
	copy(result[index+1:], result[index:])
	result[index] = element
	return result
}

func addLengthField(length int64) []byte {
	var s = big.NewInt(length) // int to big Int
	var bytes = s.Bytes()      // big Int to bytes

	for i := 0; ; i++ {
		if len(bytes) < 8 { // 8 = 8byte
			bytes = insert(bytes, 0, 0)
		} else {
			break
		}
	}
	return bytes
}

func addHeader(plainTextByte []byte) []byte {
	header := make([]byte, 2)
	header[0] = byte(default_algorithm)
	header[1] = byte(default_version)

	plainTextLength := addLengthField(int64(len(plainTextByte)))
	header = append(header, plainTextLength...)
	return header
}

//실제 Data부분의 길이
func getRawDataLen(cipherTextByte []byte) int64 {
	dataLengthByte := cipherTextByte[2:10]
	var r = big.NewInt(0).SetBytes(dataLengthByte) // bytes to big Int
	var length int64 = int64(r.Int64())            // big Int to int

	return length
}

//처음 10byte 제거
func removeHeader(cipherTextByte []byte) []byte {
	return cipherTextByte[headerLength:]
}

func removePadding(plainTextByte []byte, rawDataLength int64) []byte {
	return plainTextByte[:rawDataLength]
}

func Encrypt(keyByte []byte, nonce []byte, plainTextByte []byte) []byte {

	if optFlag {
		st_total := time.Now()
		header := addHeader(plainTextByte)
		// fmt.Println("header length:", len(header))
		// fmt.Println("plainTextByte length:", len(plainTextByte))
		if mod := len(plainTextByte) % aes.BlockSize; mod != 0 { // 블록 크기의 배수가 되어야함
			padding := make([]byte, aes.BlockSize-mod)        // 블록 크기에서 모자라는 부분을
			plainTextByte = append(plainTextByte, padding...) // 채워줌
		}

		// fmt.Println("plainTextByte length (+ pagging):", len(plainTextByte))

		// GET CIPHER BLOCK USING KEY
		block, err := aes.NewCipher(keyByte)
		checkErr(err)

		// GET CTR
		ctr := reapCipher.NewCTR(block, nonce)

		spare := 10000000
		cipherTextByte := make([]byte, len(plainTextByte)+spare)
		// ENCRYPT DATA
		bmapDataByte := ctr.XORKeyStream(cipherTextByte[spare:], plainTextByte, nil)
		fmt.Println("bmapDataByte length:", len(bmapDataByte))
		//encrypt bitmap
		cipherBmapDataLength := addLengthField(int64(len(bmapDataByte)))

		// fmt.Printf("\nplainBmapByte (original):%#v\n\n", bmapDataByte)

		if mod := len(bmapDataByte) % aes.BlockSize; mod != 0 { // 블록 크기의 배수가 되어야함
			padding := make([]byte, aes.BlockSize-mod)      // 블록 크기에서 모자라는 부분을
			bmapDataByte = append(bmapDataByte, padding...) // 채워줌
		}
		fmt.Println("bmapDataByte length (padding):", len(bmapDataByte))
		// fmt.Println("plainBmapByte: (+pagging)", len(bmapDataByte))

		ctrBitmap := reapCipher.NewCTR(block, nonce)
		cipherBmapDataByte := make([]byte, len(bmapDataByte))

		ctrBitmap.XORKeyStreamBitmap(cipherBmapDataByte, bmapDataByte)

		/////////////////////////////////////////////////////////////////////

		// //bmap 길이 field + bmapData
		// cipherBmapDataByte = append(cipherBmapDataLength, cipherBmapDataByte...)
		// // fmt.Println("cipherBmapDataByte: (+pagging & bitmapLenghByte)", len(cipherBmapDataByte))

		// cipherTextByte = append(cipherBmapDataByte, cipherTextByte...)
		// // fmt.Println("cipherBmap + ciphertext length:", len(cipherTextByte))

		// cipherTextByte = append(header, cipherTextByte...)
		// // fmt.Println("header+cipherTextByte length:", len(cipherTextByte))

		////////////////////////////////////////////////////////////////////
		l_header := len(header)
		l_cipherBmapDataLength := len(cipherBmapDataLength)
		l_cipherBmapDataByte := len(cipherBmapDataByte)
		// l_cipherTextByte := len(cipherTextByte)
		// totalSize := l_header + l_cipherBmapDataLength + l_cipherBmapDataByte + l_cipherTextByte
		// fmt.Println("totlasize:", totalSize)
		// aaa := l_header + l_cipherBmapDataLength
		// bbb := aaa + l_cipherBmapDataByte
		// totalArr := make([]byte, totalSize)

		// copy(totalArr[:l_header], header)
		// copy(totalArr[l_header:aaa], cipherBmapDataLength)
		// copy(totalArr[aaa:bbb], cipherBmapDataByte)
		// copy(totalArr[bbb:], cipherTextByte) //여기를 기존꺼를 사용할 수 있다면?? 많이 시간 단축 가능할듯

		////////////////////////////////////////////////////////////////////
		// 뒤에서부터 차곡차곡 저장
		idx_bmapDataByte := spare - l_cipherBmapDataByte
		idx_bmapDataLength := idx_bmapDataByte - l_cipherBmapDataLength
		idx_header := idx_bmapDataLength - l_header
		// fmt.Println("idx_bmapDataByte:", idx_bmapDataByte, "idx_bmapDataLength:", idx_bmapDataLength, "idx_header:", idx_header)

		copy(cipherTextByte[idx_bmapDataByte:spare], cipherBmapDataByte)
		copy(cipherTextByte[idx_bmapDataLength:idx_bmapDataByte], cipherBmapDataLength)
		copy(cipherTextByte[idx_header:idx_bmapDataLength], header)
		cipherTextByte = cipherTextByte[idx_header:]
		elap_total := time.Since(st_total)

		fmt.Println("total partial encryption time:", elap_total)
		fmt.Println("header length:", l_header)
		fmt.Println("cipherBmapDataLength length:", l_cipherBmapDataLength)
		fmt.Println("cipherBmapDataByte length:", l_cipherBmapDataByte)
		fmt.Println("cipherTextByte length", len(cipherTextByte))
		fmt.Println("plainTextByte length:", len(plainTextByte))
		// fmt.Println("totalSize:", totalSize, "cipherTextByte len:", len(cipherTextByte))

		///////////////////////////////////////////////////////////////////

		// buf := &bytes.Buffer{}
		// buf.Write(header)
		// buf.Write(cipherBmapDataLength)
		// buf.Write(cipherBmapDataByte)
		// buf.Write(cipherTextByte)
		// cipherTextByte = append(header, cipherBmapDataLength, cipherBmapDataByte, cipherTextByte...)

		return cipherTextByte
	} else {
		st_total := time.Now()
		// if mod := len(plainTextByte) % aes.BlockSize; mod != 0 { // 블록 크기의 배수가 되어야함
		// 	padding := make([]byte, aes.BlockSize-mod)        // 블록 크기에서 모자라는 부분을
		// 	plainTextByte = append(plainTextByte, padding...) // 채워줌
		// }

		// GET CIPHER BLOCK USING KEY
		block, err := aes.NewCipher(keyByte)
		checkErr(err)

		// GET CTR
		ctr := cipher.NewCTR(block, nonce)
		cipherTextByte := make([]byte, len(plainTextByte))

		// ENCRYPT DATA
		ctr.XORKeyStream(cipherTextByte, plainTextByte)

		elap_total := time.Since(st_total)
		fmt.Println("total fully encryption time:", elap_total)
		// return cipherTextByte
		return cipherTextByte
	}

}

//bmap길이 / bmap데이터 내용 / cipherText 내용 return
func pollBitmapData(cipherTextByte []byte, blockSize int) (int, []byte, []byte) {
	var r = big.NewInt(0).SetBytes(cipherTextByte[0:8]) // bytes to big Int
	var bmapDataLength int = int(r.Int64())             // big Int to int

	cipherTextByte = cipherTextByte[8:] // 8 = 8바이트 bitmap 길이 field
	var bmapDataIndex int

	mod := bmapDataLength % blockSize
	padding := blockSize - mod
	if mod != 0 {
		bmapDataIndex = bmapDataLength + padding
	} else {
		bmapDataIndex = bmapDataLength
	}
	fmt.Println("bmapDataIndex", bmapDataIndex)
	bmapDataByte := cipherTextByte[:bmapDataIndex]
	return bmapDataLength, bmapDataByte, cipherTextByte[bmapDataIndex:]
}

func Decrypt(keyByte []byte, nonce []byte, cipherTextByte []byte) []byte {
	if optFlag {
		st_total := time.Now()
		block, err := aes.NewCipher(keyByte)
		checkErr(err)

		rawDataLength := getRawDataLen(cipherTextByte)
		fmt.Println("rawDataLength:", rawDataLength)
		// fmt.Println("cipherTextByte length:", len(cipherTextByte))

		cipherTextByte = removeHeader(cipherTextByte)
		// fmt.Println("cipherTextByte length: (removed header)", len(cipherTextByte))

		bmapDataLength, cipherBmapDataByte, cipherTextByte := pollBitmapData(cipherTextByte, block.BlockSize())
		fmt.Println("bmapDataLength:", bmapDataLength, "cipherBmapDataByte length:", len(cipherBmapDataByte), "cipherTextByte length:", len(cipherTextByte))

		plainTextByte := make([]byte, len(cipherTextByte))
		plainBmapDataByte := make([]byte, len(cipherBmapDataByte))

		// GET CTR
		ctr := reapCipher.NewCTR(block, nonce)

		ctrBitmap := reapCipher.NewCTR(block, nonce)
		ctrBitmap.XORKeyStreamBitmap(plainBmapDataByte, cipherBmapDataByte)
		fmt.Println("len(cipherBmapDataByte)", len(cipherBmapDataByte))
		plainBmapDataByte = removePadding(plainBmapDataByte, int64(bmapDataLength))

		// fmt.Printf("\nplainBmapDataByte (removed pagging):%#v\n\n", plainBmapDataByte)

		// DECRYPT DATA
		bmapDataByte := ctr.XORKeyStream(plainTextByte, cipherTextByte, plainBmapDataByte)
		if bmapDataByte != nil {
			panic("decrypt must be nil..")
		}

		plainTextByte = removePadding(plainTextByte, rawDataLength)
		// fmt.Println("plainTextByte length (removed pagging):", len(plainTextByte))
		// fmt.Println("rawDataLength:", rawDataLength)

		elap_total := time.Since(st_total)
		fmt.Println("total partial decryption time:", elap_total)
		return plainTextByte
	} else {
		st_total := time.Now()
		block, err := aes.NewCipher(keyByte)
		checkErr(err)

		ctr := cipher.NewCTR(block, nonce)
		plainTextByte := make([]byte, len(cipherTextByte))

		// ENCRYPT DATA
		ctr.XORKeyStream(plainTextByte, cipherTextByte)
		elap_total := time.Since(st_total)
		fmt.Println("total fully decryption time:", elap_total)
		return plainTextByte
	}

}
