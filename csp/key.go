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
	// KeyForceProtectionHigh KeyFlag = C.CRYPT_FORCE_KEY_PROTECTION_HIGH
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

func (key Key) IsZero() bool {
	return key.hKey == 0
}

// Key extracts public key from container represented by context ctx, from
// key pair given by at parameter. It must be released after use by calling
// Close method.
func (ctx Ctx) Key(at KeyPairID) (res Key, err error) {
	return res, expectError(func() bool {
		return C.CryptGetUserKey(ctx.hProv, C.DWORD(at), &res.hKey) != 0
	}, "getting key for container")
}

// GenKey generates public/private key pair for given context. Flags parameter
// determines if generated key will be exportable or archivable and at
// parameter determines KeyExchange or Signature key pair. Resulting key must
// be eventually closed by calling Close.
func (ctx Ctx) GenKey(at KeyPairID, flags KeyFlag) (res Key, err error) {
	return res, expectError(func() bool {
		// BUG: CryptGenKey raises error NTE_FAIL. Looking into it...
		return C.CryptGenKey(ctx.hProv, C.ALG_ID(at), C.DWORD(flags), &res.hKey) != 0
	}, "creating key for container")
}

// GetParam retrieves data that governs the operations of a key.
func (key Key) GetParam(param KeyParamID) (res []byte, err error) {
	var slen C.DWORD
	if err := expectError(func() bool {
		return C.CryptGetKeyParam(key.hKey, C.DWORD(param), nil, &slen, 0) != 0
	}, "getting param's value length for key"); err != nil {
		return res, err
	}
	buf := make([]byte, slen)
	if err := expectError(func() bool {
		return C.CryptGetKeyParam(key.hKey, C.DWORD(param), (*C.BYTE)(unsafe.Pointer(&buf[0])), &slen, 0) != 0
	}, "getting param for key"); err != nil {
		return res, err
	}
	res = buf[0:int(slen)]
	return
}

// SetCipherOID sets key's cipher OID
func (key Key) SetCipherOID(oid []byte) error {
	return expectError(func() bool {
		return C.CryptSetKeyParam(key.hKey, C.KP_CIPHEROID, (*C.BYTE)(unsafe.Pointer(&oid[0])), 0) != 0
	}, "setting cipher OID for key")
}

// GetCipherOID retrieves key's cipher OID
func (key Key) GetCipherOID() ([]byte, error) {
	return key.GetParam(C.KP_CIPHEROID)
}

// GetDHOID retrieves key's DH OID
func (key Key) GetDHOID() (string, error) {
	pbytes, err := key.GetParam(C.KP_DHOID)
	if err != nil {
		return "", err
	}
	return string(pbytes[:len(pbytes)-1]), nil
}

// GetHashOID retrieves key's HASH OID
func (key Key) GetHashOID() (string, error) {
	pbytes, err := key.GetParam(C.KP_HASHOID)
	if err != nil {
		return "", err
	}
	return string(pbytes[:len(pbytes)-1]), nil
}

// GetOID retrieves key's algorithm OID
func (key Key) GetOID() (string, error) {
	pbytes, err := key.GetParam(C.KP_OID)
	if err != nil {
		return "", err
	}
	return string(pbytes[:len(pbytes)-1]), nil
}

// SetIV sets key initialization vector
func (key Key) SetIV(iv []byte) error {
	return expectError(func() bool {
		return C.CryptSetKeyParam(key.hKey, C.KP_IV, C.LPBYTE(unsafe.Pointer(&iv[0])), 0) != 0
	}, "setting IV for key")
}

// SetMode sets KP_MODE parameter on the key
func (key Key) SetMode(mode C.DWORD) error {
	return expectError(func() bool {
		return C.CryptSetKeyParam(key.hKey, C.KP_MODE, C.LPBYTE(unsafe.Pointer(&mode)), 0) != 0
	}, "setting mode for key")
}

// SetAlgID sets KP_ALGID parameter on the key
func (key Key) SetAlgID(algID C.ALG_ID) error {
	return expectError(func() bool {
		return C.CryptSetKeyParam(key.hKey, C.KP_ALGID, C.LPBYTE(unsafe.Pointer(&algID)), 0) != 0
	}, "setting algID for key")
}

// GetAlgID retrieves key's KP_ALGID parameter
func (key Key) GetAlgID() (res C.ALG_ID, err error) {
	slen := C.DWORD(unsafe.Sizeof(res))
	err = expectError(func() bool {
		return C.CryptGetKeyParam(key.hKey, C.KP_ALGID, (*C.BYTE)(unsafe.Pointer(&res)), &slen, 0) != 0
	}, "getting key ALG_ID")
	return res, err
}

// SetPadding sets KP_PADDING parameter on the key
func (key Key) SetPadding(padding C.DWORD) error {
	return expectError(func() bool {
		return C.CryptSetKeyParam(key.hKey, C.KP_PADDING, C.LPBYTE(unsafe.Pointer(&padding)), 0) != 0
	}, "setting padding for key")
}

// Close releases key handle.
func (key Key) Close() error {
	return expectError(func() bool {
		return C.CryptDestroyKey(key.hKey) != 0
	}, "releasing key")
}

// ImportPublicKeyInfo imports public key information into the context and
// returns public key
func (ctx Ctx) ImportPublicKeyInfo(cert Cert) (Key, error) {
	var res Key
	err := expectError(func() bool {
		return C.CryptImportPublicKeyInfoEx(ctx.hProv, C.MY_ENC_TYPE, &cert.pCert.pCertInfo.SubjectPublicKeyInfo, 0, 0, nil, &res.hKey) != 0
	}, "importing public key info")
	return res, err
}

// Encode exports a cryptographic key or a key pair in a secure manner. If
// cryptKey is nil, exports public key in unencrypted for, else -- session key.
func (key Key) Encode(cryptKey *Key) (SimpleBlob, error) {
	var expKey C.HCRYPTKEY
	var blobType C.DWORD = C.PUBLICKEYBLOB
	if cryptKey != nil {
		expKey = cryptKey.hKey
		blobType = C.SIMPLEBLOB
	}
	var slen C.DWORD
	if err := expectError(func() bool {
		return C.CryptExportKey(key.hKey, expKey, blobType, 0, nil, &slen) != 0
	}, "getting length for key blob"); err != nil {
		return nil, err
	}
	buf := make([]byte, slen)
	if err := expectError(func() bool {
		return C.CryptExportKey(key.hKey, expKey, blobType, 0, (*C.BYTE)(unsafe.Pointer(&buf[0])), &slen) != 0
	}, "exporting key blob"); err != nil {
		return nil, err
	}
	return SimpleBlob(buf[0:int(slen)]), nil
}

// ImportKey transfers a cryptographic key from a key BLOB into a context.
func (ctx Ctx) ImportKey(buf SimpleBlob, cryptKey *Key) (Key, error) {
	var (
		res     Key
		decrKey C.HCRYPTKEY
		errMsg  = "importing key blob"
	)
	bufBytes := C.CBytes(buf)
	defer C.free(bufBytes)
	if cryptKey != nil {
		decrKey = cryptKey.hKey
		errMsg = "importing encrypted key blob"
	}
	if err := expectError(func() bool {
		return C.CryptImportKey(ctx.hProv, (*C.BYTE)(bufBytes), C.DWORD(len(buf)), decrKey, 0, &res.hKey) != 0
	}, errMsg); err != nil {
		return res, err
	}
	return res, nil
}

// Encrypt byte data on given key
func (key Key) Encrypt(buf []byte, hash *Hash) ([]byte, error) {
	slen := C.DWORD(len(buf))
	buflen := C.DWORD(len(buf))
	var hHash C.HCRYPTHASH
	if hash != nil {
		hHash = hash.hHash
	}
	if err := expectError(func() bool {
		return C.CryptEncrypt(key.hKey, hHash, C.TRUE, 0, nil, &buflen, 0) != 0
	}, "getting encrypting data size"); err != nil {
		return nil, err
	}
	res := make([]byte, buflen)
	copy(res, buf)
	if err := expectError(func() bool {
		return C.CryptEncrypt(key.hKey, hHash, C.TRUE, 0, (*C.BYTE)(&res[0]), &slen, buflen) != 0
	}, "encrypting data"); err != nil {
		return nil, err
	}
	return res, nil
}

// Decrypt byte data on given key
func (key Key) Decrypt(buf []byte, hash *Hash) ([]byte, error) {
	slen := C.DWORD(len(buf))
	var hHash C.HCRYPTHASH
	if hash != nil {
		hHash = hash.hHash
	}
	res := make([]byte, len(buf))
	copy(res, buf)
	if err := expectError(func() bool {
		return C.CryptDecrypt(key.hKey, hHash, C.TRUE, 0, (*C.BYTE)(&res[0]), &slen) != 0
	}, "decrypting data"); err != nil {
		return res, err
	}
	return res[0:slen], nil
}
