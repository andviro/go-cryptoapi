package csp

/*
#include "common.h"

*/
import "C"

import (
	"unsafe"
)

//export msgDecodeCallback
func msgDecodeCallback(pvArg unsafe.Pointer, pbData *C.BYTE, cbData C.DWORD, fFinal bool) bool {
	msg := (*CmsDecoder)(pvArg)
	if int(cbData) > msg.maxN {
		// buffer overrun
		return false
	}
	C.memcpy(msg.data, unsafe.Pointer(pbData), C.size_t(cbData))
	msg.n = int(cbData)
	return true
}
