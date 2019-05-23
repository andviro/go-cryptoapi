package csp

/*
#include "common.h"

extern CMSG_STREAM_INFO *mkStreamInfo(void *pvArg);
*/
import "C"
import (
	"io"
	"unsafe"

	"github.com/pkg/errors"
)

// OpenToDecode creates new Msg in decode mode. If detachedSig parameter is specified,
// it must contain detached P7S signature
func OpenToDecode(src io.Reader, detachedSig ...[]byte) (msg *Msg, rErr error) {
	var (
		flags C.DWORD
		si    *C.CMSG_STREAM_INFO
	)
	res := &Msg{}
	res.callbackID = registerCallback(res.onDecode)
	if len(detachedSig) > 0 {
		flags = C.CMSG_DETACHED_FLAG
		si = nil
	} else {
		si = C.mkStreamInfo(unsafe.Pointer(&res.callbackID))
		defer C.free(unsafe.Pointer(si))
	}
	res.src = src
	res.hMsg = C.CryptMsgOpenToDecode(
		C.MY_ENC_TYPE, // encoding type
		flags,         // flags
		0,             // message type (get from message)
		0,             // default cryptographic provider
		nil,           // recipient information
		si,            // stream info
	)
	if res.hMsg == nil {
		return nil, getErr("Error opening message for decoding")
	}
	defer func() {
		if rErr == nil {
			return
		}
		if C.CryptMsgClose(res.hMsg) == 0 {
			rErr = errors.Errorf("%v (original error: %v)", getErr("Error closing message"), rErr)
		}
	}()
	for i, p := range detachedSig {
		if !res.update(p, len(p), i == len(detachedSig)-1) {
			return res, getErr("Error updating message header")
		}
	}
	pr, pw := io.Pipe()
	res.src, res.dest = pr, pw
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := src.Read(buf)
			if err != nil && err != io.EOF {
				pw.CloseWithError(err)
				return
			}
			if ok := res.update(buf, n, err == io.EOF); !ok {
				pw.CloseWithError(getErr("Error updating message body while writing"))
				return
			}
			if err == io.EOF {
				pw.CloseWithError(err)
				return
			}
		}
	}()
	return res, nil
}

// Read parses message input stream and fills buf parameter with decoded data chunk
func (msg *Msg) Read(buf []byte) (int, error) {
	return msg.src.Read(buf)
}

func (msg *Msg) onDecode(pbData *C.BYTE, cbData C.DWORD, fFinal bool) bool {
	_, msg.lastError = msg.dest.Write(C.GoBytes(unsafe.Pointer(pbData), C.int(cbData)))
	return msg.lastError == nil
}
