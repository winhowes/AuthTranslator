//go:build windows

package plugins

import (
	"fmt"
	"syscall"
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

func loadWindowsCredential(targetName, mode string) (string, error) {
	target, err := syscall.UTF16PtrFromString(targetName)
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
	return decodeCredentialBlob(blob, mode)
}
