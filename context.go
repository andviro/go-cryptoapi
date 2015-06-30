package cryptoapi

//#include "common.h"
import "C"

// Ctx is a CSP context nessessary for cryptographic
// functions.
type Ctx struct {
	hProv C.HCRYPTPROV
}

// CryptoProvider struct contains description of CSP that can be used for
// creation of CSP Context.
type CryptoProvider struct {
	Name string
	Type C.DWORD
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
		buf := C.malloc(C.size_t(slen))
		if C.CryptEnumProviders(index, nil, 0, &provType, (*C.CHAR)(buf), &slen) == 0 {
			C.free(buf)
			return res, getErr("Error during provider enumeration")
		} else {
			res = append(res, CryptoProvider{Name: C.GoString((*C.char)(buf)), Type: provType})
			C.free(buf)
		}
		index++
	}
	return res, nil
}

// NewCtx creates new CSP context from container name, provider name,
// type and flags. Empty strings for container and provider
// names are typically used for CryptVerifyContext flag setting. Created context
// must be eventually released with its Close method.
func NewCtx(container, provider string, provType ProvType, flags CryptFlag) (*Ctx, error) {
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

// Close releases CSP context
func (ctx *Ctx) Close() error {
	if C.CryptReleaseContext(ctx.hProv, 0) == 0 {
		return getErr("Error releasing context")
	}
	return nil
}
