package csp

//#include "common.h"
import "C"

import (
	"unsafe"
)

// KeyFlag sets options on created key pair
type KeyFlag C.DWORD

// Key flags
const (
	KeyArchivable KeyFlag = C.CRYPT_ARCHIVABLE
	KeyExportable KeyFlag = C.CRYPT_EXPORTABLE
	//KeyForceProtectionHigh KeyFlag = C.CRYPT_FORCE_KEY_PROTECTION_HIGH
)

// KeyPairID selects public/private key pair from CSP container
type KeyPairID C.DWORD

// Key specification
const (
	AtKeyExchange KeyPairID = C.AT_KEYEXCHANGE
	AtSignature   KeyPairID = C.AT_SIGNATURE
)

// KeyParamID represents key parameters that can be retrieved for key.
type KeyParamID C.DWORD

// Certificate parameter IDs
const (
	KeyCertificateParam KeyParamID = C.KP_CERTIFICATE // X.509 certificate that has been encoded by using DER
)

// Key incapsulates key pair functions
type Key struct {
	hKey C.HCRYPTKEY
}

func (k Key) IsZero() bool {
	return k.hKey == 0
}

// Key extracts public key from container represented by context ctx, from
// key pair given by at parameter. It must be released after use by calling
// Close method.
func (ctx Ctx) Key(at KeyPairID) (res Key, err error) {
	if C.CryptGetUserKey(ctx.hProv, C.DWORD(at), &res.hKey) == 0 {
		err = getErr("Error getting key for container")
		return
	}
	return
}

// GenKey generates public/private key pair for given context. Flags parameter
// determines if generated key will be exportable or archivable and at
// parameter determines KeyExchange or Signature key pair. Resulting key must
// be eventually closed by calling Close.
func (ctx Ctx) GenKey(at KeyPairID, flags KeyFlag) (res Key, err error) {
	if C.CryptGenKey(ctx.hProv, C.ALG_ID(at), C.DWORD(flags), &res.hKey) == 0 {
		// BUG: CryptGenKey raises error NTE_FAIL. Looking into it...
		err = getErr("Error creating key for container")
		return
	}
	return
}

// GetParam retrieves data that governs the operations of a key.
func (key Key) GetParam(param KeyParamID) (res []byte, err error) {
	var slen C.DWORD
	if C.CryptGetKeyParam(key.hKey, C.DWORD(param), nil, &slen, 0) == 0 {
		err = getErr("Error getting param's value length for key")
		return
	}

	buf := make([]byte, slen)
	if C.CryptGetKeyParam(key.hKey, C.DWORD(param), (*C.BYTE)(unsafe.Pointer(&buf[0])), &slen, 0) == 0 {
		err = getErr("Error getting param for key")
		return
	}

	res = buf[0:int(slen)]
	return
}

// Close releases key handle.
func (key Key) Close() error {
	if C.CryptDestroyKey(key.hKey) == 0 {
		return getErr("Error releasing key")
	}
	return nil
}
