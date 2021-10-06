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

func (key Key) IsZero() bool {
	return key.hKey == 0
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

// SetIV sets key initialization vector
func (key Key) SetIV(iv []byte) error {
	if C.CryptSetKeyParam(key.hKey, C.KP_IV, C.LPBYTE(unsafe.Pointer(&iv[0])), 0) == 0 {
		return getErr("Error setting IV for key")
	}
	return nil
}

// SetMode sets KP_MODE parameter on the key
func (key Key) SetMode(mode C.DWORD) error {
	if C.CryptSetKeyParam(key.hKey, C.KP_MODE, C.LPBYTE(unsafe.Pointer(&mode)), 0) == 0 {
		return getErr("Error setting mode for key")
	}
	return nil
}

// SetAlgID sets KP_ALGID parameter on the key
func (key Key) SetAlgID(algID C.ALG_ID) error {
	if C.CryptSetKeyParam(key.hKey, C.KP_MODE, C.LPBYTE(unsafe.Pointer(&algID)), 0) == 0 {
		return getErr("Error setting algID for key")
	}
	return nil
}

// GetAlgID retrieves key's KP_ALGID parameter
func (key Key) GetAlgID() (res C.ALG_ID, err error) {
	slen := C.DWORD(unsafe.Sizeof(res))
	if C.CryptGetKeyParam(key.hKey, C.KP_ALGID, (*C.BYTE)(unsafe.Pointer(&res)), &slen, 0) == 0 {
		err = getErr("Error getting key ALG_ID")
		return
	}
	return
}

// SetPadding sets KP_PADDING parameter on the key
func (key Key) SetPadding(padding C.DWORD) error {
	if C.CryptSetKeyParam(key.hKey, C.KP_PADDING, C.LPBYTE(unsafe.Pointer(&padding)), 0) == 0 {
		return getErr("Error setting padding for key")
	}
	return nil
}

// Close releases key handle.
func (key Key) Close() error {
	if C.CryptDestroyKey(key.hKey) == 0 {
		return getErr("Error releasing key")
	}
	return nil
}

// ImportPublicKeyInfo imports public key information into the context and
// returns public key
func (ctx Ctx) ImportPublicKeyInfo(cert Cert) (Key, error) {
	var res Key
	if C.CryptImportPublicKeyInfoEx(ctx.hProv, C.MY_ENC_TYPE, &cert.pCert.pCertInfo.SubjectPublicKeyInfo, 0, 0, nil, &res.hKey) == 0 {
		return res, getErr("Error importing public key info")
	}
	return res, nil
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
	if C.CryptExportKey(key.hKey, expKey, blobType, 0, nil, &slen) == 0 {
		return nil, getErr("Error getting length for key blob")
	}
	buf := make([]byte, slen)
	if C.CryptExportKey(key.hKey, expKey, blobType, 0, (*C.BYTE)(unsafe.Pointer(&buf[0])), &slen) == 0 {
		return nil, getErr("Error exporting key blob")
	}
	return SimpleBlob(buf[0:int(slen)]), nil
}

// ImportKey transfers a cryptographic key from a key BLOB into a context.
func (ctx Ctx) ImportKey(buf SimpleBlob, cryptKey *Key) (Key, error) {
	var (
		res     Key
		decrKey C.HCRYPTKEY
		errMsg  = "Error importing key blob"
	)
	bufBytes := C.CBytes(buf)
	defer C.free(bufBytes)
	if cryptKey != nil {
		decrKey = cryptKey.hKey
		errMsg = "Error importing encrypted key blob"
	}
	if C.CryptImportKey(ctx.hProv, (*C.BYTE)(bufBytes), C.DWORD(len(buf)), decrKey, 0, &res.hKey) == 0 {
		return res, getErr(errMsg)
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
	if C.CryptEncrypt(key.hKey, hHash, C.TRUE, 0, nil, &buflen, 0) == 0 {
		return nil, getErr("Error getting encrypting data size")
	}
	res := make([]byte, buflen)
	copy(res, buf)

	if C.CryptEncrypt(key.hKey, hHash, C.TRUE, 0, (*C.BYTE)(&res[0]), &slen, buflen) == 0 {
		return nil, getErr("Error encrypting data")
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
	if C.CryptDecrypt(key.hKey, hHash, C.TRUE, 0, (*C.BYTE)(&res[0]), &slen) == 0 {
		return res, getErr("Error decrypting data")
	}
	return res[0:slen], nil
}
