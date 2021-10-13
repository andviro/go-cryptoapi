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
	signerKeys []C.HCRYPTPROV_OR_NCRYPT_KEY_HANDLE
	w          io.Writer
	finalized  bool
	callbackID int64
	lastError  error
}

func (msg *Msg) flush() error {
	if msg.w != nil && !msg.finalized && !msg.update([]byte{0}, 0, true) {
		return getErr("Error flushing message")
	}
	return nil
}

// CertStore returns message certificate store. As a side-effect, source stream
// is fully read and parsed.
func (msg *Msg) CertStore() (res CertStore, err error) {
	if err = msg.flush(); err != nil {
		return
	}
	if res.hStore = C.openStoreMsg(msg.hMsg); res.hStore == nil {
		err = getErr("Error opening message cert store")
		return
	}
	return
}

// Verify verifies message signature against signer certificate
func (msg *Msg) Verify(c Cert) error {
	if C.CryptMsgControl(msg.hMsg, 0, C.CMSG_CTRL_VERIFY_SIGNATURE, unsafe.Pointer(c.pCert.pCertInfo)) == 0 {
		return getErr("Error verifying message signature")
	}
	return nil
}
