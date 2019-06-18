package csp

/*
#include "common.h"

*/
import "C"

import (
	"sync"
	"unsafe"
)

type cb func(pbData *C.BYTE, cbData C.DWORD, fFinal bool) bool

var callbacks = make(map[int64]cb)

var idx int64

var mu sync.RWMutex

func registerCallback(cb cb) int64 {
	mu.Lock()
	defer mu.Unlock()
	idx++
	callbacks[idx] = cb
	return idx
}

//export msgStreamCallback
func msgStreamCallback(pvArg unsafe.Pointer, pbData *C.BYTE, cbData C.DWORD, fFinal bool) bool {
	idx := (*int64)(pvArg)
	mu.RLock()
	defer mu.RUnlock()
	return callbacks[*idx](pbData, cbData, fFinal)
}
