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
	if got := decodeCredentialBlob(blob); got != string(blob) {
		t.Fatalf("decodeCredentialBlob() = %q, want byte fallback", got)
	}
}

func TestDecodeCredentialBlobOddLengthFallsBackToBytes(t *testing.T) {
	blob := []byte{0x61, 0x62, 0x63}
	if got := decodeCredentialBlob(blob); got != string(blob) {
		t.Fatalf("decodeCredentialBlob() = %q, want byte fallback", got)
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
