package csp

/*
#include "common.h"

BOOL WINAPI msgDecodeCallback_cgo(const void *pvArg, BYTE *pbData, DWORD cbData, BOOL fFinal);
HCERTSTORE openStoreMsg(HCRYPTMSG hMsg);
CMSG_STREAM_INFO *mkStreamInfo(const void *pvArg);

*/
import "C"

import (
	"fmt"
	"io"
	"unsafe"
)

const bufSize = 1 * 1024

// CmsDecoder encapsulates stream decoder of PKCS7 message
type CmsDecoder struct {
	Ctx
	hMsg      C.HCRYPTMSG
	src       io.Reader
	dest      io.Writer
	lastError error
}

//export msgDecodeCallback
func msgDecodeCallback(pvArg unsafe.Pointer, pbData *C.BYTE, cbData C.DWORD, fFinal bool) bool {
	msg := (*CmsDecoder)(pvArg)
	chunk := C.GoBytes(unsafe.Pointer(pbData), C.int(cbData))
	_, msg.lastError = msg.dest.Write(chunk)
	return msg.lastError == nil
}

// NewCmsDecoder creates new CmsDecoder tied to cryptographic context. If
// detachedSig parameter is specified, it must contain detached P7S signature
func NewCmsDecoder(ctx Ctx, detachedSig ...[]byte) (*CmsDecoder, error) {
	var (
		flags C.DWORD
		si    *C.CMSG_STREAM_INFO
	)
	res := &CmsDecoder{Ctx: ctx}

	if len(detachedSig) > 0 {
		flags = C.CMSG_DETACHED_FLAG
		si = nil
	} else {
		si = C.mkStreamInfo(unsafe.Pointer(res))
		defer C.free(unsafe.Pointer(si))
	}

	res.hMsg = C.CryptMsgOpenToDecode(
		C.MY_ENC_TYPE, // encoding type
		flags,         // flags
		0,             // message type (get from message)
		ctx.hProv,     // cryptographic provider
		nil,           // recipient information
		si,            // stream info
	)
	if res.hMsg == nil {
		return nil, getErr("Error opening message for decoding")
	}
	for i, p := range detachedSig {
		if !res.update(p, len(p), i == len(detachedSig)-1) {
			return nil, getErr("Error updating message header")
		}
	}
	return res, nil
}

// Close needs to be called to release internal message handle
func (m *CmsDecoder) Close() error {
	if C.CryptMsgClose(m.hMsg) == 0 {
		return getErr("Error closing CMS decoder")
	}
	return nil
}

func (m *CmsDecoder) update(buf []byte, n int, lastCall bool) bool {
	var lc C.BOOL
	if lastCall {
		lc = C.BOOL(1)
	}
	return C.CryptMsgUpdate(m.hMsg, (*C.BYTE)(unsafe.Pointer(&buf[0])), C.DWORD(n), lc) != 0
}

// Decode parses message input stream and writes decoded message body to `dest`
func (m *CmsDecoder) Decode(dest io.Writer, src io.Reader) (written int64, err error) {
	var n int
	m.dest = dest
	buf := make([]byte, bufSize)
	for {
		n, err = src.Read(buf)
		if !m.update(buf, n, err == io.EOF) {
			err = getErr("Error updating message body")
			return
		}
		written += int64(n)

		if err == io.EOF {
			err = m.lastError
			return
		}
		if err != nil {
			err = fmt.Errorf("Error reading message part: %v", err)
			return
		}
	}
}

// CertStore returns message certificates
func (m *CmsDecoder) CertStore() (*CertStore, error) {
	var res CertStore
	res.hStore = C.openStoreMsg(m.hMsg)
	if res.hStore == C.HCERTSTORE(nil) {
		return nil, getErr("Error opening message cert store")
	}
	return &res, nil
}

// Verify verifies message signature against signer certificate. Returns error if verification failed
func (m *CmsDecoder) Verify(c *Cert) error {
	if 0 == C.CryptMsgControl(m.hMsg, 0, C.CMSG_CTRL_VERIFY_SIGNATURE, unsafe.Pointer(c.pCert.pCertInfo)) {
		return getErr("Error verifying message signature")
	}
	return nil
}
