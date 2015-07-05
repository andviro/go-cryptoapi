package csp

//#include "common.h"
import "C"

// KeyFlag sets options on created key pair
type KeyFlag C.DWORD

const (
	KeyArchivable          KeyFlag = C.CRYPT_ARCHIVABLE
	KeyExportable          KeyFlag = C.CRYPT_EXPORTABLE
	KeyForceProtectionHigh KeyFlag = C.CRYPT_FORCE_KEY_PROTECTION_HIGH
)

// KeyPairId selects public/private key pair from CSP container
type KeyPairId C.DWORD

const (
	AtKeyExchange KeyPairId = C.AT_KEYEXCHANGE
	AtSignature   KeyPairId = C.AT_SIGNATURE
)

// Key incapsulates key pair functions
type Key struct {
	hKey C.HCRYPTKEY
}

// Key extracts public key from container represented by context ctx, from
// key pair given by at parameter. It must be released after use by calling
// Close method.
func (ctx *Ctx) Key(at KeyPairId) (*Key, error) {
	var hk C.HCRYPTKEY

	if C.CryptGetUserKey(ctx.hProv, C.DWORD(at), &hk) == 0 {
		return nil, getErr("Error getting key for container")
	}
	return &Key{hKey: hk}, nil
}

// GenKey generates public/private key pair for given context. Flags parameter
// determines if generated key will be exportable or archivable and at
// parameter determines KeyExchange or Signature key pair. Resulting key must
// be eventually closed by calling Close.
func (ctx *Ctx) GenKey(at KeyPairId, flags KeyFlag) (*Key, error) {
	var hk C.HCRYPTKEY

	if C.CryptGenKey(ctx.hProv, C.ALG_ID(at), C.DWORD(flags), &hk) == 0 {
		// BUG: CryptGenKey raises error NTE_FAIL. Looking into it...
		return nil, getErr("Error creating key for container")
	}
	return &Key{hKey: hk}, nil
}

// Close releases key handle.
func (key *Key) Close() error {
	if C.CryptDestroyKey(key.hKey) == 0 {
		return getErr("Error releasing key")
	}
	return nil
}
