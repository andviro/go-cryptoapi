package csp

/*
#include "common.h"

BOOL WINAPI msgDecodeCallback_cgo(const void *pvArg, BYTE *pbData, DWORD cbData, BOOL fFinal);
HCERTSTORE openStoreMsg(HCRYPTMSG hMsg);
CMSG_STREAM_INFO *mkStreamInfo(const void *pvArg);

*/
import "C"

import (
	//"fmt"
	"io"
	"unsafe"
)

const bufSize = 1 * 1024

// CmsDecoder encapsulates stream decoder of PKCS7 message
type CmsDecoder struct {
	hMsg    C.HCRYPTMSG
	src     io.Reader
	data    unsafe.Pointer
	n, maxN int
	eof     bool
}

//export msgDecodeCallback
func msgDecodeCallback(pvArg unsafe.Pointer, pbData *C.BYTE, cbData C.DWORD, fFinal bool) bool {
	msg := (*CmsDecoder)(pvArg)
	if int(cbData) > msg.maxN {
		// buffer overrun
		return false
	}
	C.memcpy(msg.data, unsafe.Pointer(pbData), C.size_t(cbData))
	msg.n = int(cbData)
	msg.eof = fFinal
	return true
}

// NewCmsDecoder creates new CmsDecoder. If detachedSig parameter is specified,
// it must contain detached P7S signature
func NewCmsDecoder(src io.Reader, detachedSig ...[]byte) (res *CmsDecoder, err error) {
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
	res.src = src
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

// Read parses message input stream and fills buf parameter with decoded data chunk
func (m *CmsDecoder) Read(buf []byte) (n int, err error) {
	nRead, err := m.src.Read(buf)
	if err != nil && err != io.EOF {
		return
	}

	m.data = unsafe.Pointer(&buf[0])
	m.n = 0
	m.maxN = len(buf)

	ok := m.update(buf, nRead, err == io.EOF)
	n = m.n
	if !ok {
		err = getErr("Error updating message body")
		return
	}
	return
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
