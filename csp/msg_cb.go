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
	return (*Msg)(pvArg).onDecode(pbData, cbData, fFinal)
}

//export msgEncodeCallback
func msgEncodeCallback(pvArg unsafe.Pointer, pbData *C.BYTE, cbData C.DWORD, fFinal bool) bool {
	return (*Msg)(pvArg).onEncode(pbData, cbData, fFinal)
}
