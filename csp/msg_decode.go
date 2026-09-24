package csp

/*
#include "common.h"

extern CMSG_STREAM_INFO *mkStreamInfo(void *pvArg);
*/
import "C"

import (
	"errors"
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
	return res, expectError(func() bool {
		res.hMsg = C.CryptMsgOpenToDecode(
			C.MY_ENC_TYPE, // encoding type
			0,             // flags
			0,             // message type (get from message)
			0,             // default cryptographic provider
			nil,           // recipient information
			si,            // stream info
		)
		if res.hMsg == nil {
			unregisterCallback(res.callbackID)
			return false
		}
		res.w = dest
		return true
	}, "Error opening message for decoding")
}

// OpenToVerify creates new Msg in decode mode. If detachedSig parameter is specified,
// it must contain detached P7S signature
func OpenToVerify(detachedSig ...[]byte) (msg *Msg, rErr error) {
	res := &Msg{}
	if err := expectError(func() bool {
		res.hMsg = C.CryptMsgOpenToDecode(
			C.MY_ENC_TYPE,        // encoding type
			C.CMSG_DETACHED_FLAG, // flags
			0,                    // message type (get from message)
			0,                    // default cryptographic provider
			nil,                  // recipient information
			nil,                  // stream info
		)
		return res.hMsg != nil
	}, "Error opening message for decoding"); err != nil {
		return nil, err
	}
	defer func() {
		if rErr == nil {
			return
		}
		rErr = errors.Join(rErr, expectError(func() bool {
			return C.CryptMsgClose(res.hMsg) != 0
		}, "Error closing message"))
	}()
	for i, p := range detachedSig {
		if err := expectError(func() bool {
			return res.update(p, len(p), i == len(detachedSig)-1)
		}, "Error updating message header"); err != nil {
			return res, err
		}
	}
	return res, nil
}

func (msg *Msg) update(buf []byte, n int, lastCall bool) bool {
	var lc C.BOOL
	if lastCall {
		lc = C.BOOL(1)
		msg.finalized = lastCall
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
