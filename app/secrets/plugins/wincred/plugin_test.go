package plugins

import (
	"context"
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestWinCredPluginLoad(t *testing.T) {
	p := winCredPlugin{}
	_, err := p.Load(context.Background(), "my-target")
	if err == nil {
		t.Fatal("expected wincred loader error on non-windows test environment")
	}
}

func TestDecodeCredentialBlobUTF16ASCII(t *testing.T) {
	blob := encodeUTF16LE("secret")
	if got := decodeCredentialBlob(blob); got != "secret" {
		t.Fatalf("decodeCredentialBlob() = %q, want %q", got, "secret")
	}
}

func TestDecodeCredentialBlobUTF16Unicode(t *testing.T) {
	want := "päss-東京-🔐"
	blob := encodeUTF16LE(want)
	if got := decodeCredentialBlob(blob); got != want {
		t.Fatalf("decodeCredentialBlob() = %q, want %q", got, want)
	}
}

func TestDecodeCredentialBlobInvalidUTF16FallsBackToBytes(t *testing.T) {
	blob := []byte{0x00, 0xD8, 0x41, 0x00} // lone high surrogate + 'A'
	if got := decodeCredentialBlob(blob); got != string(blob[:3]) {
		t.Fatalf("decodeCredentialBlob() = %q, want byte fallback", got)
	}
}

func TestDecodeCredentialBlobOddLengthFallsBackToBytes(t *testing.T) {
	blob := []byte{0x61, 0x62, 0x63}
	if got := decodeCredentialBlob(blob); got != "abc" {
		t.Fatalf("decodeCredentialBlob() = %q, want %q", got, "abc")
	}
}

func TestDecodeCredentialBlobUTF8WithTrailingNull(t *testing.T) {
	blob := append([]byte("päss-東京"), 0x00, 0x00)
	if got := decodeCredentialBlob(blob); got != "päss-東京" {
		t.Fatalf("decodeCredentialBlob() = %q, want %q", got, "päss-東京")
	}
}

func TestDecodeUTF16LEBlobInvalid(t *testing.T) {
	blob := []byte{0x00, 0xDC} // lone low surrogate
	if _, ok := decodeUTF16LEBlob(blob); ok {
		t.Fatal("expected invalid UTF-16 blob")
	}
}

func TestDecodeUTF16LEBlobEmptyAfterTrim(t *testing.T) {
	blob := []byte{0x00, 0x00}
	got, ok := decodeUTF16LEBlob(blob)
	if !ok || got != "" {
		t.Fatalf("decodeUTF16LEBlob() = (%q,%v), want (\"\",true)", got, ok)
	}
}

func TestDecodeUTF16LEBlobValidSurrogatePair(t *testing.T) {
	blob := encodeUTF16LE("🔐")
	got, ok := decodeUTF16LEBlob(blob)
	if !ok || got != "🔐" {
		t.Fatalf("decodeUTF16LEBlob() = (%q,%v), want (\"🔐\",true)", got, ok)
	}
}

func TestDecodeUTF16LEBlobInvalidHighSurrogatePairing(t *testing.T) {
	blob := []byte{0x00, 0xD8, 0x41, 0x00}
	if _, ok := decodeUTF16LEBlob(blob); ok {
		t.Fatal("expected invalid surrogate pairing")
	}
}

func TestDecodeUTF16LEBlobLoneHighSurrogate(t *testing.T) {
	blob := []byte{0x00, 0xD8}
	if _, ok := decodeUTF16LEBlob(blob); ok {
		t.Fatal("expected lone high surrogate to be invalid")
	}
}

func TestDecodeUTF16LEBlobOddLength(t *testing.T) {
	blob := []byte{0x41, 0x00, 0x42}
	if _, ok := decodeUTF16LEBlob(blob); ok {
		t.Fatal("expected odd-length blob to be invalid UTF-16")
	}
}

func encodeUTF16LE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	blob := make([]byte, (len(u16)+1)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(blob[i*2:], v)
	}
	// include a trailing UTF-16 NUL as Windows APIs commonly do.
	binary.LittleEndian.PutUint16(blob[len(u16)*2:], 0)
	return blob
}
