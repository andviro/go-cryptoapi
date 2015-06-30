package cryptoapi

/*
#cgo linux CFLAGS: -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/asn1data/
#cgo linux,amd64 LDFLAGS: -L/opt/cprocsp/lib/amd64/ -lcapi10 -lcapi20 -lasn1data -lssp
#cgo linux,386 LDFLAGS: -L/opt/cprocsp/lib/ia32/ -lcapi10 -lcapi20 -lasn1data -lssp
#cgo windows LDFLAGS: -lcrypt32 -lpthread
#include "common.h"
*/
import "C"

import (
	"unsafe"
)

type Ctx struct {
	ctx C.HCRYPTPROV
}

type CryptoProvider struct {
	Name string
	Type C.DWORD
}

func EnumProviders() ([]CryptoProvider, error) {
	var (
		slen C.DWORD
	)

	res := make([]CryptoProvider, 0)
	index := C.DWORD(0)

	for {
		var (
			provType C.DWORD
		)
		if C.CryptEnumProviders(index, nil, 0, &provType, nil, &slen) == 0 {
			return res, GetErr("Error getting initial enumeration")
		}
		buf := C.malloc(C.size_t(slen))
		if C.CryptEnumProviders(index, nil, 0, &provType, (*C.CHAR)(buf), &slen) == 0 {
			C.free(unsafe.Pointer(buf))
			return res, GetErr("Error during provider enumeration")
		} else {
			res = append(res, CryptoProvider{Name: C.GoString((*C.char)(buf)), Type: provType})
			C.free(unsafe.Pointer(buf))
		}
		index++
	}
	return res, nil
}

func NewCtx(container, provider string, provType, flags C.DWORD) (*Ctx, error) {
	var hprov C.HCRYPTPROV
	cContainer := CharPtr(container)
	cProvider := CharPtr(provider)
	defer FreePtr(cContainer)
	defer FreePtr(cProvider)

	if C.CryptAcquireContext(&hprov, cContainer, cProvider, provType, flags) == 0 {
		return nil, GetErr("Error acquiring context")
	}
	return &Ctx{ctx: hprov}, nil
}
