package csp

//#include "common.h"
import "C"

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
