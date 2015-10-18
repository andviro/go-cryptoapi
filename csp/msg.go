package csp

/*
#include "common.h"

BOOL WINAPI msgDecodeCallback_cgo(const void *pvArg, BYTE *pbData, DWORD cbData, BOOL fFinal);
HCERTSTORE openStoreMsg(HCRYPTMSG hMsg);
*/
import "C"

import (
	"fmt"
	"io"
	"unsafe"
)

// CmsDecoder encapsulates stream decoder of PKCS7 message
type CmsDecoder struct {
	hMsg      C.HCRYPTMSG
	cProv     *Ctx
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

// NewCmsDecoder creates new CmsDecoder from input stream
func NewCmsDecoder(cProv *Ctx) (*CmsDecoder, error) {

	var stStreamInfo C.CMSG_STREAM_INFO
	res := &CmsDecoder{cProv: cProv}

	stStreamInfo.cbContent = C.DWORD(0xffffffff)
	stStreamInfo.pfnStreamOutput = C.PFN_CMSG_STREAM_OUTPUT(C.msgDecodeCallback_cgo)
	stStreamInfo.pvArg = unsafe.Pointer(res)

	res.hMsg = C.CryptMsgOpenToDecode(
		C.MY_ENC_TYPE, // encoding type
		0,             // flags
		0,             // message type (get from message)
		cProv.hProv,   // cryptographic provider
		nil,           // recipient information
		&stStreamInfo,
	)
	return res, nil
}

// Close needs to be called to release internal message handle
func (m *CmsDecoder) Close() error {
	if C.CryptMsgClose(m.hMsg) == 0 {
		return getErr("Error closing CMS decoder")
	}
	return nil
}

// Decode parses message input stream and writes decoded message body to `dest`
func (m *CmsDecoder) Decode(dest io.Writer, src io.Reader) (written int64, err error) {
	var (
		lastCall C.BOOL
		n        int
	)
	m.dest = dest
	p := make([]byte, 10*1024)
	for {
		n, err = m.src.Read(p)
		if err != nil {
			lastCall = 1
		}
		if C.CryptMsgUpdate(m.hMsg, (*C.BYTE)(unsafe.Pointer(&p[0])), C.DWORD(n), lastCall) == 0 {
			err = getErr("Error decoding message part")
			return
		}
		written += int64(n)

		if err == io.EOF {
			err = m.lastError
			return
		}
		if err != nil {
			err = fmt.Errorf("Error reading message part: %v", err)
		}
		return
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

// Verify checks message signature against signer certificate. Returns non-nil error if verification failed
func (m *CmsDecoder) Verify(c *Cert) error {
	if 0 == C.CryptMsgControl(m.hMsg, 0, C.CMSG_CTRL_VERIFY_SIGNATURE, unsafe.Pointer(c.pCert.pCertInfo)) {
		return getErr("Error verifying message signature")
	}
	return nil
}
