package csp

/*
#include "common.h"

extern CMSG_STREAM_INFO *mkStreamInfo(void *pvArg);
*/
import "C"
import (
	"fmt"
	"io"
	"unsafe"
)

// OpenToDecode creates new Msg in decode mode. If detachedSig parameter is specified,
// it must contain detached P7S signature
func OpenToDecode(dest io.Writer) (msg *Msg, rErr error) {
	res := &Msg{}
	res.callbackID = registerCallback(res.onWrite)
	si := C.mkStreamInfo(unsafe.Pointer(&res.callbackID))
	defer C.free(unsafe.Pointer(si))
	res.hMsg = C.CryptMsgOpenToDecode(
		C.MY_ENC_TYPE, // encoding type
		0,             // flags
		0,             // message type (get from message)
		0,             // default cryptographic provider
		nil,           // recipient information
		si,            // stream info
	)
	if res.hMsg == nil {
		return nil, getErr("Error opening message for decoding")
	}
	res.w = dest
	return res, nil
}

// OpenToVerify creates new Msg in decode mode. If detachedSig parameter is specified,
// it must contain detached P7S signature
func OpenToVerify(detachedSig ...[]byte) (msg *Msg, rErr error) {
	res := &Msg{}
	res.hMsg = C.CryptMsgOpenToDecode(
		C.MY_ENC_TYPE,        // encoding type
		C.CMSG_DETACHED_FLAG, // flags
		0,                    // message type (get from message)
		0,                    // default cryptographic provider
		nil,                  // recipient information
		nil,                  // stream info
	)
	if res.hMsg == nil {
		return nil, getErr("Error opening message for decoding")
	}
	defer func() {
		if rErr == nil {
			return
		}
		if C.CryptMsgClose(res.hMsg) == 0 {
			rErr = fmt.Errorf("%v (original error: %v)", getErr("Error closing message"), rErr)
		}
	}()
	for i, p := range detachedSig {
		if !res.update(p, len(p), i == len(detachedSig)-1) {
			return res, getErr("Error updating message header")
		}
	}
	return res, nil
}

func (msg *Msg) update(buf []byte, n int, lastCall bool) bool {
	var lc C.BOOL
	if lastCall {
		lc = C.BOOL(1)
	}
	return C.CryptMsgUpdate(msg.hMsg, (*C.BYTE)(unsafe.Pointer(&buf[0])), C.DWORD(n), lc) != 0
}

func (msg *Msg) onWrite(pbData *C.BYTE, cbData C.DWORD, fFinal bool) bool {
	if msg.w != nil {
		if _, err := msg.w.Write(C.GoBytes(unsafe.Pointer(pbData), C.int(cbData))); err != nil {
			msg.lastError = err
		}
	}
	return msg.lastError == nil
}
