package csp

/*
#include "common.h"

*/
import "C"

import (
	"fmt"
	"hash"
	"unsafe"
)

// Hash encapsulates GOST hash
type Hash struct {
	hHash  C.HCRYPTHASH
	hKey   C.HCRYPTKEY
	hProv  C.HCRYPTPROV
	length int
}

func (h *Hash) cAlg() C.ALG_ID {
	switch h.length {
	case 2001:
		return C.CALG_GR3411
	case 512:
		return C.CALG_GR3411_2012_512
	}
	return C.CALG_GR3411_2012_256
}

type HashOpt func(dest *Hash)

func HashCtx(ctx Ctx) HashOpt {
	return func(dest *Hash) {
		dest.hProv = ctx.hProv
	}
}

func HashKey(key Key) HashOpt {
	return func(dest *Hash) {
		dest.hKey = key.hKey
	}
}

var _ hash.Hash = (*Hash)(nil)

func NewHash(length int, options ...HashOpt) (*Hash, error) {
	res := &Hash{}
	for _, opt := range options {
		opt(res)
	}
	if res.hProv == 0 {
		ctx, err := AcquireCtx("", "", ProvGost2012_512, CryptVerifyContext)
		if err != nil {
			return nil, err
		}
		res.hProv = ctx.hProv
	}
	if C.CryptCreateHash(res.hProv, res.cAlg(), res.hKey, 0, &res.hHash) == 0 {
		return nil, getErr("Error creating hash")
	}
	return res, nil
}

func (h *Hash) Close() error {
	if C.CryptDestroyHash(h.hHash) == 0 {
		return getErr("Error destroying hash")
	}
	return nil
}

func (h *Hash) Write(buf []byte) (n int, err error) {
	if C.CryptHashData(h.hHash, (*C.BYTE)(unsafe.Pointer(&buf[0])), C.DWORD(len(buf)), 0) == 0 {
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
	fmt.Println("***", n)
	res := make([]byte, int(n))
	if C.CryptGetHashParam(h.hHash, C.HP_HASHVAL, (*C.BYTE)(&res[0]), &n, 0) == 0 {
		panic(getErr("Error getting hash value"))
	}
	return res
}

// Reset resets the Hash to its initial state.
func (h *Hash) Reset() {
	panic("not implemented") // TODO: Implement
}

// Size returns the number of bytes Sum will return.
func (h *Hash) Size() int {
	if h.length == 512 {
		return 64
	}
	return 32
}

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (h *Hash) BlockSize() int {
	if h.length == 2001 {
		return 32
	}
	return 64
}
