package csp

/*
#include "common.h"

*/
import "C"

import (
	"unsafe"
)

//export msgUpdateCallback
func msgUpdateCallback(pvArg unsafe.Pointer, pbData *C.BYTE, cbData C.DWORD, fFinal bool) bool {
	return (*Msg)(pvArg).updateCallback(pbData, cbData, fFinal) == nil
}
