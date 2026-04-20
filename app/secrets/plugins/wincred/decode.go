package plugins

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
	"unicode/utf8"
)

// decodeCredentialBlob converts Windows credential blobs into a string.
//
// CredMan generic credentials are often stored as UTF-16LE text, but callers
// can write arbitrary bytes. We therefore:
//   - prefer UTF-8 when bytes are valid UTF-8 text without embedded NULs,
//   - otherwise decode valid UTF-16LE,
//   - and finally fall back to raw bytes with trailing NULs removed.
func decodeCredentialBlob(blob []byte) string {
	trimmed := bytes.TrimRight(blob, "\x00")
	if utf8.Valid(trimmed) && !bytes.Contains(trimmed, []byte{0x00}) {
		return string(trimmed)
	}

	if s, ok := decodeUTF16LEBlob(blob); ok {
		return s
	}

	return string(trimmed)
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
