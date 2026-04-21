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

func TestWinCredPluginLoadInvalidID(t *testing.T) {
	p := winCredPlugin{}
	if _, err := p.Load(context.Background(), "#utf8"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestParseWinCredID(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantTgt   string
		wantMode  string
		wantError bool
	}{
		{name: "default raw", input: "target", wantTgt: "target", wantMode: "raw"},
		{name: "utf8 mode", input: "target#utf8", wantTgt: "target", wantMode: "utf8"},
		{name: "utf16 mode", input: "target#utf16le", wantTgt: "target", wantMode: "utf16le"},
		{name: "invalid mode", input: "target#auto", wantError: true},
		{name: "missing target", input: "   #utf8", wantError: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target, mode, err := parseWinCredID(tc.input)
			if tc.wantError {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if target != tc.wantTgt || mode != tc.wantMode {
				t.Fatalf("parseWinCredID(%q) = (%q,%q), want (%q,%q)", tc.input, target, mode, tc.wantTgt, tc.wantMode)
			}
		})
	}
}

func TestDecodeCredentialBlobRaw(t *testing.T) {
	blob := []byte{0x00, 0xAB, 0xCD, 0xEF}
	got, err := decodeCredentialBlob(blob, "raw")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != string(blob) {
		t.Fatalf("decodeCredentialBlob(raw) = %q, want raw bytes", got)
	}
}

func TestDecodeCredentialBlobUTF8(t *testing.T) {
	blob := []byte("päss-東京")
	got, err := decodeCredentialBlob(blob, "utf8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "päss-東京" {
		t.Fatalf("decodeCredentialBlob(utf8) = %q", got)
	}
}

func TestDecodeCredentialBlobUTF8Invalid(t *testing.T) {
	blob := []byte{0xff, 0xfe}
	if _, err := decodeCredentialBlob(blob, "utf8"); err == nil {
		t.Fatal("expected utf8 decode error")
	}
}

func TestDecodeCredentialBlobUTF16ASCII(t *testing.T) {
	blob := encodeUTF16LE("secret")
	got, err := decodeCredentialBlob(blob, "utf16le")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "secret" {
		t.Fatalf("decodeCredentialBlob(utf16le) = %q, want %q", got, "secret")
	}
}

func TestDecodeCredentialBlobUTF16WithBOM(t *testing.T) {
	blob := append([]byte{0xFF, 0xFE}, encodeUTF16LE("secret")...)
	got, err := decodeCredentialBlob(blob, "utf16le")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "secret" {
		t.Fatalf("decodeCredentialBlob(utf16le) = %q, want %q", got, "secret")
	}
}

func TestDecodeCredentialBlobUTF16UnicodeNoTerminator(t *testing.T) {
	blob := encodeUTF16LENoTerminator("東京🔐")
	got, err := decodeCredentialBlob(blob, "utf16le")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "東京🔐" {
		t.Fatalf("decodeCredentialBlob(utf16le) = %q, want %q", got, "東京🔐")
	}
}

func TestDecodeCredentialBlobUTF16Invalid(t *testing.T) {
	blob := []byte{0x00, 0xD8, 0x41, 0x00}
	if _, err := decodeCredentialBlob(blob, "utf16le"); err == nil {
		t.Fatal("expected utf16 decode error")
	}
}

func TestDecodeCredentialBlobUnsupportedMode(t *testing.T) {
	if _, err := decodeCredentialBlob([]byte("x"), "bogus"); err == nil {
		t.Fatal("expected unsupported mode error")
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

func encodeUTF16LENoTerminator(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	blob := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(blob[i*2:], v)
	}
	return blob
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
