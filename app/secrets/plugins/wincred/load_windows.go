//go:build windows

package plugins

import (
	"fmt"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

const credTypeGeneric = 1

type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        syscall.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

var (
	advapi32  = syscall.NewLazyDLL("advapi32.dll")
	procReadW = advapi32.NewProc("CredReadW")
	procFree  = advapi32.NewProc("CredFree")
)

func loadWindowsCredential(id string) (string, error) {
	target, err := syscall.UTF16PtrFromString(id)
	if err != nil {
		return "", err
	}

	var credPtr uintptr
	r1, _, callErr := procReadW.Call(
		uintptr(unsafe.Pointer(target)),
		uintptr(credTypeGeneric),
		0,
		uintptr(unsafe.Pointer(&credPtr)),
	)
	if r1 == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return "", fmt.Errorf("credread failed: %w", callErr)
		}
		return "", fmt.Errorf("credread failed")
	}
	defer procFree.Call(credPtr)

	cred := (*credential)(unsafe.Pointer(credPtr))
	if cred.CredentialBlob == nil || cred.CredentialBlobSize == 0 {
		return "", fmt.Errorf("credential has no secret data")
	}

	blob := unsafe.Slice(cred.CredentialBlob, cred.CredentialBlobSize)
	return decodeCredentialBlob(blob), nil
}

func decodeCredentialBlob(blob []byte) string {
	if len(blob)%2 == 0 {
		u16 := make([]uint16, 0, len(blob)/2)
		looksUTF16 := true
		for i := 0; i < len(blob); i += 2 {
			v := uint16(blob[i]) | uint16(blob[i+1])<<8
			u16 = append(u16, v)
			if blob[i+1] != 0 {
				looksUTF16 = false
			}
		}
		if looksUTF16 {
			for len(u16) > 0 && u16[len(u16)-1] == 0 {
				u16 = u16[:len(u16)-1]
			}
			return string(utf16.Decode(u16))
		}
	}
	return string(blob)
}
