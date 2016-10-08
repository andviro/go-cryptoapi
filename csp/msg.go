package csp

/*
#include "common.h"

BOOL WINAPI msgDecodeCallback_cgo(
    const void *pvArg,
    BYTE *pbData,
    DWORD cbData,
    BOOL fFinal)
{
	return msgDecodeCallback(pvArg, pbData, cbData, fFinal);
}

HCERTSTORE openStoreMsg(HCRYPTMSG hMsg) {
	return CertOpenStore(CERT_STORE_PROV_MSG, MY_ENC_TYPE, 0, CERT_STORE_CREATE_NEW_FLAG, hMsg);
}

CMSG_STREAM_INFO *mkStreamInfo(void *pvArg) {
	CMSG_STREAM_INFO *res = malloc(sizeof(CMSG_STREAM_INFO));
	memset(res, 0, sizeof(CMSG_STREAM_INFO));
	res->cbContent = 0xffffffff;
	res->pfnStreamOutput = &msgDecodeCallback_cgo;
	res->pvArg = pvArg;
	return res;
}

*/
import "C"

import (
	//"fmt"
	"io"
	"io/ioutil"
	"unsafe"
)

// CmsDecoder encapsulates stream decoder of PKCS7 message
type CmsDecoder struct {
	hMsg    C.HCRYPTMSG
	src     io.Reader
	data    unsafe.Pointer
	n, maxN int
	eof     bool
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
	if m.eof {
		return 0, io.EOF
	}
	nRead, err := m.src.Read(buf)
	if err != nil && err != io.EOF {
		return
	}

	m.data = unsafe.Pointer(&buf[0])
	m.n = 0
	m.maxN = len(buf)
	m.eof = (err == io.EOF)

	ok := m.update(buf, nRead, m.eof)
	n = m.n
	if !ok {
		err = getErr("Error updating message body")
		return
	}
	return
}

// CertStore returns message certificate store. As a side-effect, source stream
// is fully read and parsed.
func (m *CmsDecoder) CertStore() (res CertStore, err error) {
	if _, err = ioutil.ReadAll(m); err != nil {
		return
	}
	if res.hStore = C.openStoreMsg(m.hMsg); res.hStore == nil {
		err = getErr("Error opening message cert store")
		return
	}
	return
}

// Verify verifies message signature against signer certificate. As a
// side-effect, source stream is fully read and parsed.
func (m *CmsDecoder) Verify(c Cert) (err error) {
	if _, err = ioutil.ReadAll(m); err != nil {
		return
	}
	if 0 == C.CryptMsgControl(m.hMsg, 0, C.CMSG_CTRL_VERIFY_SIGNATURE, unsafe.Pointer(c.pCert.pCertInfo)) {
		return getErr("Error verifying message signature")
	}
	return nil
}
