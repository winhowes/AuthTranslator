package plugins

import (
	"encoding/binary"
	"unicode/utf16"
)

func decodeCredentialBlob(blob []byte) string {
	if len(blob)%2 != 0 {
		return string(blob)
	}

	u16 := make([]uint16, len(blob)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = binary.LittleEndian.Uint16(blob[i*2:])
	}

	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	if len(u16) == 0 {
		return ""
	}

	if !isValidUTF16(u16) {
		return string(blob)
	}

	return string(utf16.Decode(u16))
}

func isValidUTF16(u16 []uint16) bool {
	for i := 0; i < len(u16); i++ {
		v := u16[i]
		if v >= 0xD800 && v <= 0xDBFF {
			if i+1 >= len(u16) {
				return false
			}
			next := u16[i+1]
			if next < 0xDC00 || next > 0xDFFF {
				return false
			}
			i++
			continue
		}
		if v >= 0xDC00 && v <= 0xDFFF {
			return false
		}
	}
	return true
}
