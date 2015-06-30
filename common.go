package cryptoapi

/*
#include "common.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

const (
	CryptVerifyContext = C.CRYPT_VERIFYCONTEXT
	CryptNewKeyset     = C.CRYPT_NEWKEYSET
	CryptMachineKeyset = C.CRYPT_MACHINE_KEYSET
	CryptDeleteKeyset  = C.CRYPT_DELETEKEYSET
	CryptSilent        = C.CRYPT_SILENT
)

const (
	ProvRsa      = C.PROV_RSA_FULL
	ProvGost94   = 71
	ProvGost2001 = 75
)

func CharPtr(s string) *C.CHAR {
	if s != "" {
		return (*C.CHAR)(unsafe.Pointer(C.CString(s)))
	}
	return nil
}

func FreePtr(s *C.CHAR) {
	C.free(unsafe.Pointer(s))
}

func GetErr(msg string) error {
	return errors.New(fmt.Sprintf("%s: %x", msg, C.GetLastError()))
}
