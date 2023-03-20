package bitmap

import "fmt"

// The Max Size is 0x01 << 32 at present(can expand to 0x01 << 64)
const BitmapSize = 0x01 << 32

type Bitmap struct {
	// bitmap 저장소
	data []byte `json:"data"`
	// bit 갯수
	bitsize uint64 `json:"bitsize"`
	// SetBit 중 가장 큰 offset 값
	maxpos uint64 `json:"maxpos"`
}

func NewBitmap() *Bitmap {
	return NewBitmapSize(BitmapSize)
}

func (bitmap *Bitmap) GetData() []byte {
	return bitmap.data
}

func NewBitmapSize(size int) *Bitmap {
	// fmt.Println(size)
	if size == 0 || size > BitmapSize {
		size = BitmapSize
	} else if remainder := size % 8; remainder != 0 {
		size += 8 - remainder
	}

	//size>>3 의미: bit -> byte
	return &Bitmap{data: make([]byte, size>>3), bitsize: uint64(size)}
}

func (bitmap *Bitmap) SetBit(offset uint64, value uint8) bool {
	index, pos := offset/8, offset%8

	if bitmap.bitsize <= offset {
		return false
	}

	if value == 0 {

		bitmap.data[index] &^= 0x01 << pos
	} else {
		bitmap.data[index] |= 0x01 << pos

		if bitmap.maxpos < offset {
			bitmap.maxpos = offset
		}
	}

	return true
}

func (bitmap *Bitmap) GetBit(offset uint64) uint8 {
	index, pos := offset/8, offset%8

	if bitmap.bitsize <= offset {
		return 0
	}

	return (bitmap.data[index] >> pos) & 0x01
}

func (bitmap *Bitmap) Maxpos() uint64 {
	return bitmap.maxpos
}

func (bitmap *Bitmap) String() string {
	var maxTotal, bitTotal uint64 = 10000000000000, bitmap.maxpos + 1

	if bitmap.maxpos > maxTotal {
		bitTotal = maxTotal
	}

	numSlice := make([]uint64, 0, bitTotal)

	var offset uint64
	for offset = 0; offset < bitTotal; offset++ {
		if bitmap.GetBit(offset) == 1 {
			numSlice = append(numSlice, offset)
		}
	}

	return fmt.Sprintf("%v", numSlice)
}
