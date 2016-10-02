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
	hMsg      C.HCRYPTMSG
	dest      io.Writer
	written   int
	lastError error
}

//export msgDecodeCallback
func msgDecodeCallback(pvArg unsafe.Pointer, pbData *C.BYTE, cbData C.DWORD, fFinal bool) bool {
	msg := (*CmsDecoder)(pvArg)
	if msg.dest == nil {
		return true
	}

	var n int
	chunk := C.GoBytes(unsafe.Pointer(pbData), C.int(cbData))
	n, msg.lastError = msg.dest.Write(chunk)
	msg.written += n
	return msg.lastError == nil
}

// NewCmsDecoder creates new CmsDecoder. If detachedSig parameter is specified,
// it must contain detached P7S signature
func NewCmsDecoder(detachedSig ...[]byte) (res *CmsDecoder, err error) {
	var (
		flags C.DWORD
		si    *C.CMSG_STREAM_INFO
	)
	res = new(CmsDecoder)

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
		0,             // default cryptographic provider
		nil,           // recipient information
		si,            // stream info
	)
	if res.hMsg == nil {
		err = getErr("Error opening message for decoding")
		return
	}
	for i, p := range detachedSig {
		if !res.update(p, len(p), i == len(detachedSig)-1) {
			err = getErr("Error updating message header")
			return
		}
	}
	return
}

// Close needs to be called to release internal message handle
func (m CmsDecoder) Close() error {
	if C.CryptMsgClose(m.hMsg) == 0 {
		return getErr("Error closing CMS decoder")
	}
	return nil
}

func (m CmsDecoder) update(buf []byte, n int, lastCall bool) bool {
	var lc C.BOOL
	if lastCall {
		lc = C.BOOL(1)
	}
	return C.CryptMsgUpdate(m.hMsg, (*C.BYTE)(unsafe.Pointer(&buf[0])), C.DWORD(n), lc) != 0
}

// Decode parses message input stream from `src` and writes decoded message body to `dest`.
func (m *CmsDecoder) Decode(dest io.Writer, src io.Reader) (written int64, err error) {
	var n int
	m.written = 0
	m.dest = dest
	buf := make([]byte, bufSize)
	for {
		n, err = src.Read(buf)
		ok := m.update(buf, n, err == io.EOF)
		written = int64(m.written)

		if !ok {
			err = getErr("Error updating message body")
			return
		}
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
func (m CmsDecoder) CertStore() (res CertStore, err error) {
	if res.hStore = C.openStoreMsg(m.hMsg); res.hStore == nil {
		err = getErr("Error opening message cert store")
		return
	}
	return
}

// Verify verifies message signature against signer certificate. Returns error if verification failed
func (m CmsDecoder) Verify(c Cert) error {
	if 0 == C.CryptMsgControl(m.hMsg, 0, C.CMSG_CTRL_VERIFY_SIGNATURE, unsafe.Pointer(c.pCert.pCertInfo)) {
		return getErr("Error verifying message signature")
	}
	return nil
}
