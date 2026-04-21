package plugins

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

func decodeCredentialBlob(blob []byte, mode string) (string, error) {
	switch mode {
	case "raw":
		return string(blob), nil
	case "utf8":
		if !utf8.Valid(blob) {
			return "", fmt.Errorf("credential blob is not valid utf-8")
		}
		return string(blob), nil
	case "utf16le":
		s, ok := decodeUTF16LEBlob(blob)
		if !ok {
			return "", fmt.Errorf("credential blob is not valid utf-16le")
		}
		return s, nil
	default:
		return "", fmt.Errorf("unsupported decode mode %q", mode)
	}
}

func decodeUTF16LEBlob(blob []byte) (string, bool) {
	if len(blob)%2 != 0 {
		return "", false
	}

	u16 := make([]uint16, len(blob)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = binary.LittleEndian.Uint16(blob[i*2:])
	}

	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	if len(u16) > 0 && u16[0] == 0xFEFF {
		u16 = u16[1:]
	}
	if len(u16) == 0 {
		return "", true
	}

	if !isValidUTF16(u16) {
		return "", false
	}

	return string(utf16.Decode(u16)), true
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
