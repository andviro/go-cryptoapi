package csp

//#include "common.h"
import "C"

import (
	"fmt"
	"unsafe"
)

type SimpleBlob []byte

type SessionKey struct {
	SeanceKey          []byte
	EncryptedKey       []byte
	MACKey             []byte
	EncryptionParamSet []byte
}

func (s SimpleBlob) ToSessionKey() (SessionKey, error) {
	var res SessionKey
	if C.DWORD(len(s)) != C.DWORD(unsafe.Sizeof(C.CRYPT_SIMPLEBLOB{})) {
		return res, fmt.Errorf("invalid blob size")
	}
	sb := (*C.CRYPT_SIMPLEBLOB)(unsafe.Pointer(&s[0]))
}
