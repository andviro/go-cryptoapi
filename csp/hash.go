package csp

/*
#include "common.h"

*/
import "C"

import (
	"encoding/asn1"
	"hash"
	"unsafe"
)

// Hash encapsulates GOST hash
type Hash struct {
	hHash          C.HCRYPTHASH
	hKey           C.HCRYPTKEY
	hProv          C.HCRYPTPROV
	algID          C.ALG_ID
	dwKeySpec      C.DWORD
	mustReleaseCtx C.BOOL
	keyHash        *Hash
}

var _ hash.Hash = (*Hash)(nil)

// HashOptions describe hash creation parameters
type HashOptions struct {
	HashAlg  asn1.ObjectIdentifier // Hash algorithm ID
	SignCert Cert                  // Certificate with a reference to private key container used to sign the hash
	HMACKey  Key                   // HMAC key for creating hash in HMAC mode
}

func (ho *HashOptions) cAlg(hmac bool) C.ALG_ID {
	switch {
	case GOST_R3411.Equal(ho.HashAlg):
		if hmac {
			return C.CALG_GR3411_HMAC
		}
		return C.CALG_GR3411
	case GOST_R3411_12_512.Equal(ho.HashAlg):
		if hmac {
			return C.CALG_GR3411_2012_512_HMAC
		}
		return C.CALG_GR3411_2012_512
	}
	if hmac {
		return C.CALG_GR3411_2012_256_HMAC
	}
	return C.CALG_GR3411_2012_256
}

func NewHash(options HashOptions) (*Hash, error) {
	res := &Hash{algID: options.cAlg(!options.HMACKey.IsZero())}
	if !options.HMACKey.IsZero() {
		res.hKey = options.HMACKey.hKey
	}
	if options.SignCert.IsZero() {
		ctx, err := AcquireCtx("", "", ProvGost2012_512, CryptVerifyContext)
		if err != nil {
			return nil, err
		}
		res.hProv = ctx.hProv
		res.mustReleaseCtx = C.TRUE
	} else if C.CryptAcquireCertificatePrivateKey(options.SignCert.pCert, 0, nil, &res.hProv, &res.dwKeySpec, &res.mustReleaseCtx) == 0 {
		return nil, getErr("Error acquiring certificate private key")
	}
	if C.CryptCreateHash(res.hProv, res.algID, res.hKey, 0, &res.hHash) == 0 {
		return nil, getErr("Error creating hash")
	}
	return res, nil
}

func (h *Hash) Close() error {
	if C.CryptDestroyHash(h.hHash) == 0 {
		return getErr("Error destroying hash")
	}
	if h.mustReleaseCtx != 0 && C.CryptReleaseContext(h.hProv, 0) == 0 {
		return getErr("Error releasing context")
	}
	if h.keyHash != nil {
		return h.keyHash.Close()
	}
	return nil
}

func (h *Hash) Write(buf []byte) (n int, err error) {
	var ptr unsafe.Pointer
	if len(buf) > 0 {
		ptr = unsafe.Pointer(&buf[0])
	}
	if C.CryptHashData(h.hHash, (*C.BYTE)(ptr), C.DWORD(len(buf)), 0) == 0 {
		return 0, getErr("Error updating hash")
	}
	return n, nil
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (h *Hash) Sum(b []byte) []byte {
	if len(b) != 0 {
		_, err := h.Write(b)
		if err != nil {
			panic(err)
		}
	}
	var n C.DWORD
	slen := C.DWORD(C.sizeof_DWORD)
	if C.CryptGetHashParam(h.hHash, C.HP_HASHSIZE, (*C.uchar)(unsafe.Pointer(&n)), &slen, 0) == 0 {
		panic(getErr("Error getting hash size"))
	}
	res := make([]byte, int(n))
	if C.CryptGetHashParam(h.hHash, C.HP_HASHVAL, (*C.BYTE)(&res[0]), &n, 0) == 0 {
		panic(getErr("Error getting hash value"))
	}
	return res
}

// Reset resets the Hash to its initial state.
func (h *Hash) Reset() {
	if C.CryptDestroyHash(h.hHash) == 0 {
		panic(getErr("Error destroying hash"))
	}
	if C.CryptCreateHash(h.hProv, h.algID, h.hKey, 0, &h.hHash) == 0 {
		panic(getErr("Error creating hash"))
	}
}

// Size returns the number of bytes Sum will return.
func (h *Hash) Size() int {
	if h.algID == C.CALG_GR3411_2012_512 {
		return 64
	}
	return 32
}

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (h *Hash) BlockSize() int {
	if h.algID == C.CALG_GR3411 {
		return 32
	}
	return 64
}

func (h *Hash) Sign() ([]byte, error) {
	var slen C.DWORD
	if C.CryptSignHash(h.hHash, h.dwKeySpec, nil, 0, nil, &slen) == 0 {
		return nil, getErr("Error calculating signature size")
	}
	if slen == 0 {
		return nil, nil
	}
	res := make([]byte, int(slen))
	if C.CryptSignHash(h.hHash, h.dwKeySpec, nil, 0, (*C.BYTE)(&res[0]), &slen) == 0 {
		return nil, getErr("Error calculating signature value")
	}
	return res, nil
}

func (h *Hash) Verify(signer Cert, sig []byte) error {
	var hPubKey C.HCRYPTKEY
	// Get the public key from the certificate
	if C.CryptImportPublicKeyInfo(h.hProv, C.MY_ENC_TYPE, &signer.pCert.pCertInfo.SubjectPublicKeyInfo, &hPubKey) == 0 {
		return getErr("Error getting certificate public key handle")
	}
	var ptr unsafe.Pointer
	if len(sig) > 0 {
		ptr = unsafe.Pointer(&sig[0])
	}
	if C.CryptVerifySignature(h.hHash, (*C.BYTE)(ptr), C.DWORD(len(sig)), hPubKey, nil, 0) == 0 {
		return getErr("Error verifying hash signature")
	}
	return nil
}

// NewHMAC creates HMAC object initialized with given byte key
func NewHMAC(hashAlg asn1.ObjectIdentifier, key []byte) (_ *Hash, rErr error) {
	opts := HashOptions{HashAlg: hashAlg}
	keyHash, err := NewHash(opts)
	if err != nil {
		return nil, err
	}
	defer func() {
		if rErr != nil {
			keyHash.Close()
		}
	}()
	if _, err := keyHash.Write(key); err != nil {
		return nil, err
	}
	if C.CryptDeriveKey(keyHash.hProv, C.CALG_G28147, keyHash.hHash, C.CRYPT_EXPORTABLE, &opts.HMACKey.hKey) == 0 {
		return nil, getErr("Error deriving key")
	}
	res, err := NewHash(opts)
	if err != nil {
		return nil, err
	}
	res.keyHash = keyHash
	return res, nil
}
