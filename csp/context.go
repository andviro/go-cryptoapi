package csp

//#include "common.h"
import "C"

import (
	"unsafe"
)

// CryptFlag determines behaviour of acquired context
type CryptFlag C.DWORD

const (
	CryptVerifyContext CryptFlag = C.CRYPT_VERIFYCONTEXT
	CryptNewKeyset     CryptFlag = C.CRYPT_NEWKEYSET
	CryptMachineKeyset CryptFlag = C.CRYPT_MACHINE_KEYSET
	CryptDeleteKeyset  CryptFlag = C.CRYPT_DELETEKEYSET
	CryptSilent        CryptFlag = C.CRYPT_SILENT
)

// ProvType is CryptoAPI provider type
type ProvType C.DWORD

const (
	ProvRsa      ProvType = C.PROV_RSA_FULL
	ProvGost94   ProvType = 71
	ProvGost2001 ProvType = 75
)

// Ctx is a CSP context nessessary for cryptographic
// functions.
type Ctx struct {
	hProv C.HCRYPTPROV
}

// CryptoProvider struct contains description of CSP that can be used for
// creation of CSP Context.
type CryptoProvider struct {
	Name string
	Type ProvType
}

// EnumProviders returns slice of CryptoProvider structures, describing
// available CSPs.
func EnumProviders() ([]CryptoProvider, error) {
	var (
		slen C.DWORD
	)

	res := make([]CryptoProvider, 0)
	index := C.DWORD(0)

	for {
		var provType C.DWORD

		if C.CryptEnumProviders(index, nil, 0, &provType, nil, &slen) == 0 {
			break
		}
		buf := make([]byte, slen)
		// XXX: Some evil magic here
		if C.CryptEnumProviders(index, nil, 0, &provType, (*C.CHAR)(unsafe.Pointer(&buf[0])), &slen) == 0 {
			return res, getErr("Error during provider enumeration")
		} else {
			res = append(res, CryptoProvider{Name: string(buf), Type: ProvType(provType)})
		}
		index++
	}
	return res, nil
}

// AcquireCtx acquires new CSP context from container name, provider name,
// type and flags. Empty strings for container and provider
// names are typically used for CryptVerifyContext flag setting. Created context
// must be eventually released with its Close method.
func AcquireCtx(container, provider string, provType ProvType, flags CryptFlag) (*Ctx, error) {
	var hprov C.HCRYPTPROV
	cContainer := charPtr(container)
	cProvider := charPtr(provider)
	defer freePtr(cContainer)
	defer freePtr(cProvider)

	if C.CryptAcquireContext(&hprov, cContainer, cProvider, C.DWORD(provType), C.DWORD(flags)) == 0 {
		return nil, getErr("Error acquiring context")
	}
	return &Ctx{hProv: hprov}, nil
}

//RemoveCtx deletes key container from CSP.
func DeleteCtx(container, provider string, provType ProvType) error {
	_, err := AcquireCtx(container, provider, provType, CryptDeleteKeyset)
	return err
}

// Close releases CSP context
func (ctx *Ctx) Close() error {
	if C.CryptReleaseContext(ctx.hProv, 0) == 0 {
		return getErr("Error releasing context")
	}
	return nil
}

// SetPassword changes PIN on key container acquired with AcquireCtx to pwd. Which
// private/public key pair affected is determined by at parameter.
func (ctx *Ctx) SetPassword(pwd string, at KeyPairId) error {
	var pParam C.DWORD
	pin := unsafe.Pointer(C.CString(pwd))
	defer C.free(pin)

	if at == AtSignature {
		pParam = C.PP_SIGNATURE_PIN
	} else {
		pParam = C.PP_KEYEXCHANGE_PIN
	}
	if C.CryptSetProvParam(ctx.hProv, pParam, (*C.BYTE)(pin), 0) == 0 {
		return getErr("Error setting container password")
	}
	return nil
}
