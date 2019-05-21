package csp

/*
#include "common.h"

typedef struct {
	BYTE *pbData;
	DWORD cbData;
	DWORD capacity;
	BOOL final;
} slice;

typedef slice *PSLICE;

static slice *mkSlice() {
	slice *res = malloc(sizeof(slice));
	memset(res, 0, sizeof(slice));
	return res;
}

static BOOL WINAPI msgUpdateCallback(
    const void *pvArg,
    BYTE *pbData,
    DWORD cbData,
    BOOL fFinal)
{
	PSLICE target = (PSLICE)pvArg;
	size_t newSize = target->cbData + cbData;
	if (target->capacity < newSize) {
		target->capacity = newSize * 2;
		target->pbData = realloc(target->pbData, target->capacity);
	}
	memcpy(&target->pbData[target->cbData], pbData, cbData);
	target->cbData = newSize;
	target->final = fFinal;
	return 1;
}

static HCERTSTORE openStoreMsg(HCRYPTMSG hMsg) {
	return CertOpenStore(CERT_STORE_PROV_MSG, MY_ENC_TYPE, 0, CERT_STORE_CREATE_NEW_FLAG, hMsg);
}

static CMSG_STREAM_INFO *mkStreamInfo(PSLICE target) {
	CMSG_STREAM_INFO *res = malloc(sizeof(CMSG_STREAM_INFO));
	memset(res, 0, sizeof(CMSG_STREAM_INFO));
	res->cbContent = 0xffffffff;
	res->pfnStreamOutput = &msgUpdateCallback;
	res->pvArg = (PVOID)target;
	return res;
}

static CMSG_SIGNED_ENCODE_INFO *mkSignedInfo(int n) {
	int i;

	CMSG_SIGNED_ENCODE_INFO *res = malloc(sizeof(CMSG_SIGNED_ENCODE_INFO));
	memset(res, 0, sizeof(CMSG_SIGNED_ENCODE_INFO));
	res->cbSize = sizeof(CMSG_SIGNED_ENCODE_INFO);

	res->cSigners = n;
	res->rgSigners = (PCMSG_SIGNER_ENCODE_INFO) malloc(sizeof(CMSG_SIGNER_ENCODE_INFO) * n);
	memset(res->rgSigners, 0, sizeof(CMSG_SIGNER_ENCODE_INFO) * n);

	res->cCertEncoded = n;
	res->rgCertEncoded =  malloc(sizeof(CERT_BLOB) * n);
	memset(res->rgCertEncoded, 0, sizeof(CERT_BLOB) * n);

	return res;
}

static void setSignedInfo(CMSG_SIGNED_ENCODE_INFO *out, int n, HCRYPTPROV hCryptProv, PCCERT_CONTEXT pSignerCert, DWORD dwKeySpec, LPSTR oid) {
	out->rgSigners[n].cbSize = sizeof(CMSG_SIGNER_ENCODE_INFO);
	out->rgSigners[n].pCertInfo = pSignerCert->pCertInfo;
	out->rgSigners[n].hCryptProv = hCryptProv;
	out->rgSigners[n].dwKeySpec = dwKeySpec;
	out->rgSigners[n].HashAlgorithm.pszObjId = oid;
	out->rgSigners[n].pvHashAuxInfo = NULL;

	out->rgCertEncoded[n].cbData = pSignerCert->cbCertEncoded;
	out->rgCertEncoded[n].pbData = pSignerCert->pbCertEncoded;
}

static void freeSignedInfo(CMSG_SIGNED_ENCODE_INFO *info) {
	free(info->rgCertEncoded);
	free(info->rgSigners);
	free(info);
}

static BYTE *tailPointer(BYTE *data, int n) {
	return &data[n];
}

*/
import "C"

import (
	"encoding/asn1"
	"fmt"
	"io"
	"io/ioutil"
	"sync"
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
	hMsg      C.HCRYPTMSG
	src       io.Reader
	dest      io.Writer
	data      C.PSLICE
	tail      []byte
	lastError error
}

var slicePool = &sync.Pool{
	New: func() interface{} {
		return unsafe.Pointer(C.mkSlice())
	},
}

// EncodeOptions specifies message creation details
type EncodeOptions struct {
	Detached   bool                  // Signature is detached
	HashAlg    asn1.ObjectIdentifier // Signature hash algorithm ID
	Signers    []Cert                // Signing certificate list
	Recipients []Cert                // Recipients list for encryption
}

// OpenToDecode creates new Msg in decode mode. If detachedSig parameter is specified,
// it must contain detached P7S signature
func OpenToDecode(src io.Reader, detachedSig ...[]byte) (res *Msg, err error) {
	var (
		flags C.DWORD
		si    *C.CMSG_STREAM_INFO
	)
	res = &Msg{
		data: C.PSLICE(slicePool.Get().(unsafe.Pointer)),
	}
	if len(detachedSig) > 0 {
		flags = C.CMSG_DETACHED_FLAG
		si = nil
	} else {
		si = C.mkStreamInfo(res.data)
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
	res.src = src
	for i, p := range detachedSig {
		if !res.update(p, len(p), i == len(detachedSig)-1) {
			err = getErr("Error updating message header")
			return
		}
	}
	return
}

// OpenToEncode creates new Msg in encode mode.
func OpenToEncode(dest io.Writer, options EncodeOptions) (res *Msg, err error) {
	var flags C.DWORD

	res = &Msg{
		data: C.PSLICE(slicePool.Get().(unsafe.Pointer)),
	}
	res.data.cbData = 0

	if len(options.Signers) == 0 {
		err = fmt.Errorf("Signer certificates list is empty")
		return
	}
	if options.HashAlg == nil {
		options.HashAlg = GOST_R3411
	}
	if options.Detached {
		flags = C.CMSG_DETACHED_FLAG
	}

	si := C.mkStreamInfo(res.data)
	defer C.free(unsafe.Pointer(si))

	signedInfo := C.mkSignedInfo(C.int(len(options.Signers)))
	defer C.freeSignedInfo(signedInfo)

	hashOID := C.CString(options.HashAlg.String())
	defer C.free(unsafe.Pointer(hashOID))

	for i, signerCert := range options.Signers {
		var (
			hCryptProv C.HCRYPTPROV_OR_NCRYPT_KEY_HANDLE
			dwKeySpec  C.DWORD
		)
		if 0 == C.CryptAcquireCertificatePrivateKey(signerCert.pCert, 0, nil, &hCryptProv, &dwKeySpec, nil) {
			err = getErr("Error acquiring certificate private key")
			return
		}
		C.setSignedInfo(signedInfo, C.int(i), C.HCRYPTPROV(hCryptProv), signerCert.pCert, dwKeySpec, (*C.CHAR)(hashOID))
	}

	res.hMsg = C.CryptMsgOpenToEncode(
		C.MY_ENC_TYPE,              // encoding type
		flags,                      // flags
		C.CMSG_SIGNED,              // message type
		unsafe.Pointer(signedInfo), // pointer to structure
		nil,                        // inner content OID
		si,                         // stream information
	)
	if res.hMsg == nil {
		err = getErr("Error opening message for encoding")
		return
	}
	res.dest = dest
	return
}

// Close needs to be called to release internal message handle. When in encode mode,
// it also closes the underlying writer if it implements io.Closer
func (msg *Msg) Close() error {
	defer slicePool.Put(unsafe.Pointer(msg.data))
	if msg.dest != nil {
		msg.data.cbData = 0
		if !msg.update([]byte{0}, 0, true) {
			return getErr("Error finalizing message")
		}
		_, err := msg.dest.Write(C.GoBytes(unsafe.Pointer(msg.data.pbData), C.int(msg.data.cbData)))
		if err != nil {
			return err
		}
	}
	msg.data.cbData = 0
	if C.CryptMsgClose(msg.hMsg) == 0 {
		return getErr("Error closing message")
	}
	return nil
}

func (msg *Msg) update(buf []byte, n int, lastCall bool) bool {
	var lc C.BOOL
	if lastCall {
		lc = C.BOOL(1)
	}
	return C.CryptMsgUpdate(msg.hMsg, (*C.BYTE)(unsafe.Pointer(&buf[0])), C.DWORD(n), lc) != 0
}

// Read parses message input stream and fills buf parameter with decoded data chunk
func (msg *Msg) Read(buf []byte) (int, error) {
	if len(msg.tail) > 0 || msg.lastError != nil {
		return msg.drain(buf)
	}
	nRead, err := msg.src.Read(buf)
	if err != nil && err != io.EOF {
		return nRead, err
	}
	msg.lastError = err
	msg.data.cbData = 0
	if ok := msg.update(buf, nRead, (err == io.EOF)); !ok {
		return 0, getErr("Error updating message body")
	}
	msg.tail = C.GoBytes(unsafe.Pointer(msg.data.pbData), C.int(msg.data.cbData))
	return msg.drain(buf)
}

func (msg *Msg) drain(buf []byte) (int, error) {
	if len(msg.tail) > len(buf) {
		copy(buf, msg.tail[:len(buf)])
		msg.tail = msg.tail[len(buf):]
		return len(buf), nil
	}
	copy(buf, msg.tail)
	n := len(msg.tail)
	msg.tail = nil
	return n, msg.lastError
}

// Write encodes provided bytes into message output data stream
func (msg *Msg) Write(buf []byte) (int, error) {
	msg.data.cbData = 0
	if ok := msg.update(buf, len(buf), false); !ok {
		return 0, getErr("Error updating message body")
	}
	_, err := msg.dest.Write(C.GoBytes(unsafe.Pointer(msg.data.pbData), C.int(msg.data.cbData)))
	return len(buf), err
}

// CertStore returns message certificate store. As a side-effect, source stream
// is fully read and parsed.
func (msg *Msg) CertStore() (*CertStore, error) {
	if _, err := ioutil.ReadAll(msg); err != nil {
		return nil, err
	}
	res := new(CertStore)
	if res.hStore = C.openStoreMsg(msg.hMsg); res.hStore == nil {
		return nil, getErr("Error opening message cert store")
	}
	return res, nil
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
