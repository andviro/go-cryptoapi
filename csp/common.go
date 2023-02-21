// Package csp provides mid-level cryptographic API based on CryptoAPI
// 2.0 on Windows and CryptoPro CSP on Linux.
package csp

/*
#cgo darwin CFLAGS: -I/opt/cprocsp/include/cpcsp
#cgo darwin LDFLAGS: -L/opt/cprocsp/lib -lcapi10 -lcapi20 -lrdrsup -lssp
#cgo linux,amd64 CFLAGS: -I/opt/cprocsp/include/cpcsp -DUNIX -DLINUX -DSIZEOF_VOID_P=8
#cgo linux,386 CFLAGS: -I/opt/cprocsp/include/cpcsp -DUNIX -DLINUX -DSIZEOF_VOID_P=4
#cgo linux,amd64 LDFLAGS: -L/opt/cprocsp/lib/amd64/ -lcapi10 -lcapi20 -lrdrsup -lssp
#cgo linux,386 LDFLAGS: -L/opt/cprocsp/lib/ia32/ -lcapi10 -lcapi20 -lrdrsup -lssp
#cgo windows CFLAGS: -I/opt/cprocsp/include/cpcsp
#cgo windows LDFLAGS: -lcrypt32 -lpthread
#include "common.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// ErrorCode corresponds to a C type DWORD
type ErrorCode C.DWORD

func (ec ErrorCode) String() string {
	if s, ok := errorStringMap[int64(ec)]; ok {
		return s
	}
	actualCode := C.DWORD(ec)
	return fmt.Sprintf("%#010x", actualCode)
}

// Some C error codes translated to Go constants
const (
	ErrBadKeysetParam ErrorCode = C.NTE_BAD_KEYSET_PARAM & (1<<32 - 1) // Typically occurs when trying to acquire context
	ErrFail           ErrorCode = C.NTE_FAIL & (1<<32 - 1)             // Misc error
	// ErrInvalidParameter ErrorCode = C.NTE_INVALID_PARAMETER & (1<<32 - 1) // Bad parameter to cryptographic function
	ErrNoKey          ErrorCode = C.NTE_NO_KEY & (1<<32 - 1)                   // Key not found
	ErrExists         ErrorCode = C.NTE_EXISTS & (1<<32 - 1)                   // Object already exists
	ErrNotFound       ErrorCode = C.NTE_NOT_FOUND & (1<<32 - 1)                // Object not found
	ErrKeysetNotDef   ErrorCode = C.NTE_KEYSET_NOT_DEF & (1<<32 - 1)           // Operation on unknown container
	ErrBadKeyset      ErrorCode = C.NTE_BAD_KEYSET & (1<<32 - 1)               // Operation on unknown container
	ErrStreamNotReady ErrorCode = C.CRYPT_E_STREAM_MSG_NOT_READY & (1<<32 - 1) // Returned until stream header is parsed
	ErrCryptNotFound  ErrorCode = C.CRYPT_E_NOT_FOUND & (1<<32 - 1)
	ErrMoreData       ErrorCode = C.ERROR_MORE_DATA & (1<<32 - 1)
)

// Error provides error type
type Error struct {
	Code ErrorCode // Code indicates exact CryptoAPI error code
	msg  string
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.msg, e.Code)
}

func charPtr(s string) *C.CHAR {
	if s != "" {
		return (*C.CHAR)(unsafe.Pointer(C.CString(s)))
	}
	return nil
}

func freePtr(s *C.CHAR) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

func getErr(msg string) error {
	return Error{msg: msg, Code: ErrorCode(C.GetLastError())}
}

func extractBlob(pb *C.DATA_BLOB) []byte {
	return C.GoBytes(unsafe.Pointer(pb.pbData), C.int(pb.cbData))
}
