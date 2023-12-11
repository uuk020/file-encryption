package internal

import (
	"strconv"
)

func RotateLeft(lValue uint32, iShiftBits uint32) uint32 {
	return (lValue << iShiftBits) | (lValue >> (32 - iShiftBits))
}

func AddUnsigned(lX uint32, lY uint32) uint32 {
	var lX4, lY4, lX8, lY8, lResult uint32
	lX8 = (lX & 0x80000000)
	lY8 = (lY & 0x80000000)
	lX4 = (lX & 0x40000000)
	lY4 = (lY & 0x40000000)
	lResult = (lX & 0x3FFFFFFF) + (lY & 0x3FFFFFFF)
	if (lX4 & lY4) != 0 {
		return (lResult ^ 0x80000000 ^ lX8 ^ lY8)
	}
	if (lX4 | lY4) != 0 {
		if (lResult & 0x40000000) != 0 {
			return (lResult ^ 0xC0000000 ^ lX8 ^ lY8)
		} else {
			return (lResult ^ 0x40000000 ^ lX8 ^ lY8)
		}
	} else {
		return (lResult ^ lX8 ^ lY8)
	}
}

func F(x, y, z uint32) uint32 {
	return (x & y) | ((^x) & z)
}

func G(x, y, z uint32) uint32 {
	return (x & z) | (y & (^z))
}

func H(x, y, z uint32) uint32 {
	return x ^ y ^ z
}

func I(x, y, z uint32) uint32 {
	return y ^ (x | (^z))
}

func FF(a, b, c, d, x, s, ac uint32) uint32 {
	a = AddUnsigned(a, AddUnsigned(AddUnsigned(F(b, c, d), x), ac))
	return AddUnsigned(RotateLeft(a, s), b)
}

func GG(a, b, c, d, x, s, ac uint32) uint32 {
	a = AddUnsigned(a, AddUnsigned(AddUnsigned(G(b, c, d), x), ac))
	return AddUnsigned(RotateLeft(a, s), b)
}

func HH(a, b, c, d, x, s, ac uint32) uint32 {
	a = AddUnsigned(a, AddUnsigned(AddUnsigned(H(b, c, d), x), ac))
	return AddUnsigned(RotateLeft(a, s), b)
}

func II(a, b, c, d, x, s, ac uint32) uint32 {
	a = AddUnsigned(a, AddUnsigned(AddUnsigned(I(b, c, d), x), ac))
	return AddUnsigned(RotateLeft(a, s), b)
}

func ConvertToWordArray(code string) []uint32 {
	lMessageLength := len(code)
	lNumberOfWords_temp1 := lMessageLength + 8
	lNumberOfWords_temp2 := (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64
	lNumberOfWords := (lNumberOfWords_temp2 + 1) * 16
	lWordArray := make([]uint32, lNumberOfWords)
	lBytePosition := uint32(0)
	lByteCount := 0

	for lByteCount < lMessageLength {
		lWordCount := (lByteCount - (lByteCount % 4)) / 4
		lBytePosition = uint32(lByteCount%4) * 8
		lWordArray[lWordCount] = lWordArray[lWordCount] | (uint32(code[lByteCount]) << lBytePosition)
		lByteCount++
	}

	lWordCount := (lByteCount - (lByteCount % 4)) / 4
	lBytePosition = uint32(lByteCount%4) * 8
	lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition)
	lWordArray[lNumberOfWords-2] = uint32(lMessageLength) << 3
	lWordArray[lNumberOfWords-1] = uint32(lMessageLength) >> 29

	return lWordArray
}

func WordToHex(lValue uint32) string {
	var WordToHexValue, WordToHexValue_temp string
	var lByte, lCount uint32

	for lCount <= 3 {
		lByte = (lValue >> (lCount * 8)) & 255
		WordToHexValue_temp = "0" + strconv.FormatUint(uint64(lByte), 16)
		WordToHexValue = WordToHexValue + WordToHexValue_temp[len(WordToHexValue_temp)-2:]
		lCount++
	}

	return WordToHexValue
}

func GenerateKey(code string, bit uint8) []byte {
	var x = ConvertToWordArray(code)

	var k, AA, BB, CC, DD, a, b, c, d uint32

	S11, S12, S13, S14 := uint32(7), uint32(12), uint32(17), uint32(22)
	S21, S22, S23, S24 := uint32(5), uint32(9), uint32(14), uint32(20)
	S31, S32, S33, S34 := uint32(4), uint32(11), uint32(16), uint32(23)
	S41, S42, S43, S44 := uint32(6), uint32(10), uint32(15), uint32(21)

	a = 0x67452301
	b = 0xEFCDAB89
	c = 0x98BADCFE
	d = 0x10325476
	for k = 0; k < uint32(len(x)); k += 16 {
		AA = a
		BB = b
		CC = c
		DD = d
		a = FF(a, b, c, d, x[k+0], S11, 0xD76AA478)
		d = FF(d, a, b, c, x[k+1], S12, 0xE8C7B756)
		c = FF(c, d, a, b, x[k+2], S13, 0x242070DB)
		b = FF(b, c, d, a, x[k+3], S14, 0xC1BDCEEE)
		a = FF(a, b, c, d, x[k+4], S11, 0xF57C0FAF)
		d = FF(d, a, b, c, x[k+5], S12, 0x4787C62A)
		c = FF(c, d, a, b, x[k+6], S13, 0xA8304613)
		b = FF(b, c, d, a, x[k+7], S14, 0xFD469501)
		a = FF(a, b, c, d, x[k+8], S11, 0x698098D8)
		d = FF(d, a, b, c, x[k+9], S12, 0x8B44F7AF)
		c = FF(c, d, a, b, x[k+10], S13, 0xFFFF5BB1)
		b = FF(b, c, d, a, x[k+11], S14, 0x895CD7BE)
		a = FF(a, b, c, d, x[k+12], S11, 0x6B901122)
		d = FF(d, a, b, c, x[k+13], S12, 0xFD987193)
		c = FF(c, d, a, b, x[k+14], S13, 0xA679438E)
		b = FF(b, c, d, a, x[k+15], S14, 0x49B40821)
		a = GG(a, b, c, d, x[k+1], S21, 0xF61E2562)
		d = GG(d, a, b, c, x[k+6], S22, 0xC040B340)
		c = GG(c, d, a, b, x[k+11], S23, 0x265E5A51)
		b = GG(b, c, d, a, x[k+0], S24, 0xE9B6C7AA)
		a = GG(a, b, c, d, x[k+5], S21, 0xD62F105D)
		d = GG(d, a, b, c, x[k+10], S22, 0x2441453)
		c = GG(c, d, a, b, x[k+15], S23, 0xD8A1E681)
		b = GG(b, c, d, a, x[k+4], S24, 0xE7D3FBC8)
		a = GG(a, b, c, d, x[k+9], S21, 0x21E1CDE6)
		d = GG(d, a, b, c, x[k+14], S22, 0xC33707D6)
		c = GG(c, d, a, b, x[k+3], S23, 0xF4D50D87)
		b = GG(b, c, d, a, x[k+8], S24, 0x455A14ED)
		a = GG(a, b, c, d, x[k+13], S21, 0xA9E3E905)
		d = GG(d, a, b, c, x[k+2], S22, 0xFCEFA3F8)
		c = GG(c, d, a, b, x[k+7], S23, 0x676F02D9)
		b = GG(b, c, d, a, x[k+12], S24, 0x8D2A4C8A)
		a = HH(a, b, c, d, x[k+5], S31, 0xFFFA3942)
		d = HH(d, a, b, c, x[k+8], S32, 0x8771F681)
		c = HH(c, d, a, b, x[k+11], S33, 0x6D9D6122)
		b = HH(b, c, d, a, x[k+14], S34, 0xFDE5380C)
		a = HH(a, b, c, d, x[k+1], S31, 0xA4BEEA44)
		d = HH(d, a, b, c, x[k+4], S32, 0x4BDECFA9)
		c = HH(c, d, a, b, x[k+7], S33, 0xF6BB4B60)
		b = HH(b, c, d, a, x[k+10], S34, 0xBEBFBC70)
		a = HH(a, b, c, d, x[k+13], S31, 0x289B7EC6)
		d = HH(d, a, b, c, x[k+0], S32, 0xEAA127FA)
		c = HH(c, d, a, b, x[k+3], S33, 0xD4EF3085)
		b = HH(b, c, d, a, x[k+6], S34, 0x4881D05)
		a = HH(a, b, c, d, x[k+9], S31, 0xD9D4D039)
		d = HH(d, a, b, c, x[k+12], S32, 0xE6DB99E5)
		c = HH(c, d, a, b, x[k+15], S33, 0x1FA27CF8)
		b = HH(b, c, d, a, x[k+2], S34, 0xC4AC5665)
		a = II(a, b, c, d, x[k+0], S41, 0xF4292244)
		d = II(d, a, b, c, x[k+7], S42, 0x432AFF97)
		c = II(c, d, a, b, x[k+14], S43, 0xAB9423A7)
		b = II(b, c, d, a, x[k+5], S44, 0xFC93A039)
		a = II(a, b, c, d, x[k+12], S41, 0x655B59C3)
		d = II(d, a, b, c, x[k+3], S42, 0x8F0CCC92)
		c = II(c, d, a, b, x[k+10], S43, 0xFFEFF47D)
		b = II(b, c, d, a, x[k+1], S44, 0x85845DD1)
		a = II(a, b, c, d, x[k+8], S41, 0x6FA87E4F)
		d = II(d, a, b, c, x[k+15], S42, 0xFE2CE6E0)
		c = II(c, d, a, b, x[k+6], S43, 0xA3014314)
		b = II(b, c, d, a, x[k+13], S44, 0x4E0811A1)
		a = II(a, b, c, d, x[k+4], S41, 0xF7537E82)
		d = II(d, a, b, c, x[k+11], S42, 0xBD3AF235)
		c = II(c, d, a, b, x[k+2], S43, 0x2AD7D2BB)
		b = II(b, c, d, a, x[k+9], S44, 0xEB86D391)
		a = AddUnsigned(a, AA)
		b = AddUnsigned(b, BB)
		c = AddUnsigned(c, CC)
		d = AddUnsigned(d, DD)
	}
	if bit == 32 {
		return []byte(WordToHex(a) + WordToHex(b) + WordToHex(c) + WordToHex(d))
	}
	return []byte(WordToHex(b) + WordToHex(c))
}
