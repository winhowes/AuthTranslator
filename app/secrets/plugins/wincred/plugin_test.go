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

func TestDecodeCredentialBlobUTF16WithBOM(t *testing.T) {
	blob := append([]byte{0xFF, 0xFE}, encodeUTF16LE("secret")...)
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

func TestDecodeCredentialBlobShortEvenWithSingleZeroFallsBack(t *testing.T) {
	blob := []byte{0x00, 0xAB, 0xCD, 0xEF}
	if got := decodeCredentialBlob(blob); got != string(blob) {
		t.Fatalf("decodeCredentialBlob() = %q, want raw bytes", got)
	}
}

func TestDecodeCredentialBlobInvalidUTF16FallsBackToBytes(t *testing.T) {
	blob := []byte{0x00, 0xD8, 0x41, 0x00} // lone high surrogate + 'A'
	if got := decodeCredentialBlob(blob); got != string(blob) {
		t.Fatalf("decodeCredentialBlob() = %q, want byte fallback", got)
	}
}

func TestDecodeCredentialBlobOddLengthFallsBackToBytes(t *testing.T) {
	blob := []byte{0x61, 0x62, 0x63}
	if got := decodeCredentialBlob(blob); got != "abc" {
		t.Fatalf("decodeCredentialBlob() = %q, want %q", got, "abc")
	}
}

func TestDecodeCredentialBlobEvenLengthNonUTF16Binary(t *testing.T) {
	blob := []byte{0x80, 0x81, 0x82, 0x83}
	if got := decodeCredentialBlob(blob); got != string(blob) {
		t.Fatalf("decodeCredentialBlob() = %q, want raw bytes", got)
	}
}

func TestLooksLikeUTF16LE(t *testing.T) {
	tests := []struct {
		name string
		blob []byte
		want bool
	}{
		{name: "odd length", blob: []byte{0x41}, want: false},
		{name: "bom", blob: []byte{0xFF, 0xFE, 0x41, 0x00}, want: true},
		{name: "ascii utf16 style", blob: []byte{0x41, 0x00, 0x42, 0x00}, want: true},
		{name: "short even one zero", blob: []byte{0x00, 0xAB, 0xCD, 0xEF}, want: false},
		{name: "null terminated plausible utf16", blob: []byte{0x71, 0x67, 0xAC, 0x4E, 0x00, 0x00}, want: true},
		{name: "binary without nul pattern", blob: []byte{0x80, 0x81, 0x82, 0x83}, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikeUTF16LE(tc.blob); got != tc.want {
				t.Fatalf("looksLikeUTF16LE(%v) = %v, want %v", tc.blob, got, tc.want)
			}
		})
	}
}

func TestDecodeCredentialBlobUTF8WithTrailingNull(t *testing.T) {
	blob := append([]byte("päss-東京"), 0x00, 0x00)
	if got := decodeCredentialBlob(blob); got != "päss-東京" {
		t.Fatalf("decodeCredentialBlob() = %q, want %q", got, "päss-東京")
	}
}

func TestIsProbablyText(t *testing.T) {
	if !isProbablyText("hello東京\n\r\t") {
		t.Fatal("expected printable text to be accepted")
	}
	if !isProbablyText("") {
		t.Fatal("expected empty string to be accepted")
	}
	if isProbablyText("bad\x01text") {
		t.Fatal("expected control-character text to be rejected")
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
