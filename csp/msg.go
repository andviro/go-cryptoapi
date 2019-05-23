package csp

/*
#include "common.h"

static HCERTSTORE openStoreMsg(HCRYPTMSG hMsg) {
	return CertOpenStore(CERT_STORE_PROV_MSG, MY_ENC_TYPE, 0, CERT_STORE_CREATE_NEW_FLAG, hMsg);
}

extern BOOL WINAPI msgStreamCallback(
    const void *pvArg,
    BYTE *pbData,
    DWORD cbData,
    BOOL fFinal);

CMSG_STREAM_INFO *mkStreamInfo(void *pvArg) {
	CMSG_STREAM_INFO *res = malloc(sizeof(CMSG_STREAM_INFO));
	memset(res, 0, sizeof(CMSG_STREAM_INFO));
	res->cbContent = CMSG_INDEFINITE_LENGTH;
	res->pfnStreamOutput = &msgStreamCallback;
	res->pvArg = pvArg;
	return res;
}

*/
import "C"

import (
	"encoding/asn1"
	"io"
	"io/ioutil"
	"unsafe"
)

// Common object identifiers
var (
	GOST_R3411        asn1.ObjectIdentifier = []int{1, 2, 643, 2, 2, 9}
	GOST_R3411_12_256 asn1.ObjectIdentifier = []int{1, 2, 643, 7, 1, 1, 2, 2}
	GOST_R3411_12_512 asn1.ObjectIdentifier = []int{1, 2, 643, 7, 1, 1, 2, 3}

	MD5RSA      asn1.ObjectIdentifier = []int{1, 2, 840, 113549, 1, 1, 4}
	SHA1RSA     asn1.ObjectIdentifier = []int{1, 2, 840, 113549, 1, 1, 5}
	SETOAEP_RSA asn1.ObjectIdentifier = []int{1, 2, 840, 113549, 1, 1, 6}

	SHA256RSA asn1.ObjectIdentifier = []int{1, 2, 840, 113549, 1, 1, 11}
	SHA384RSA asn1.ObjectIdentifier = []int{1, 2, 840, 113549, 1, 1, 12}
	SHA512RSA asn1.ObjectIdentifier = []int{1, 2, 840, 113549, 1, 1, 13}
)

// Msg encapsulates stream decoder of PKCS7 message
type Msg struct {
	hMsg       C.HCRYPTMSG
	src        io.Reader
	dest       io.Writer
	callbackID int64
	lastError  error
}

func (msg *Msg) update(buf []byte, n int, lastCall bool) bool {
	var lc C.BOOL
	if lastCall {
		lc = C.BOOL(1)
	}
	return C.CryptMsgUpdate(msg.hMsg, (*C.BYTE)(unsafe.Pointer(&buf[0])), C.DWORD(n), lc) != 0
}

// CertStore returns message certificate store. As a side-effect, source stream
// is fully read and parsed.
func (msg *Msg) CertStore() (res CertStore, err error) {
	if _, err = ioutil.ReadAll(msg); err != nil {
		return
	}
	if res.hStore = C.openStoreMsg(msg.hMsg); res.hStore == nil {
		err = getErr("Error opening message cert store")
		return
	}
	return
}

// Verify verifies message signature against signer certificate. As a
// side-effect, source stream is fully read and parsed.
func (msg *Msg) Verify(c Cert) (err error) {
	if _, err = ioutil.ReadAll(msg); err != nil {
		return
	}
	if 0 == C.CryptMsgControl(msg.hMsg, 0, C.CMSG_CTRL_VERIFY_SIGNATURE, unsafe.Pointer(c.pCert.pCertInfo)) {
		return getErr("Error verifying message signature")
	}
	return nil
}
