package plugins

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
	"unicode/utf8"
)

// decodeCredentialBlob converts a CredentialBlob to text conservatively.
//
// For CRED_TYPE_GENERIC, CredentialBlob is application-defined bytes. To avoid
// corrupting non-UTF16 blobs, we only decode as UTF-16LE when the payload looks
// like UTF-16LE (BOM or enough NUL-byte structure). Otherwise we keep bytes as-is.
func decodeCredentialBlob(blob []byte) string {
	trimmedNUL := bytes.TrimRight(blob, "\x00")
	if utf8.Valid(trimmedNUL) && !bytes.Contains(trimmedNUL, []byte{0x00}) {
		return string(trimmedNUL)
	}

	if looksLikeUTF16LE(blob) {
		if s, ok := decodeUTF16LEBlob(blob); ok {
			return s
		}
	}

	return string(blob)
}

func looksLikeUTF16LE(blob []byte) bool {
	if len(blob) < 2 || len(blob)%2 != 0 {
		return false
	}

	// UTF-16LE BOM.
	if len(blob) >= 2 && blob[0] == 0xFF && blob[1] == 0xFE {
		return true
	}

	// Heuristic: UTF-16 text often contains many zero bytes in one parity (ASCII
	// in UTF-16LE has zeros at odd indices) or explicit NUL terminators.
	oddZeros, evenZeros := 0, 0
	for i, b := range blob {
		if b != 0 {
			continue
		}
		if i%2 == 0 {
			evenZeros++
		} else {
			oddZeros++
		}
	}

	threshold := len(blob) / 4
	if threshold == 0 {
		threshold = 1
	}

	return oddZeros >= threshold || evenZeros >= threshold
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
