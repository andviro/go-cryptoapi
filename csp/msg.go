package csp

/*
#include "common.h"

static HCERTSTORE openStoreMsg(HCRYPTMSG hMsg) {
	return CertOpenStore(CERT_STORE_PROV_MSG, MY_ENC_TYPE, 0, CERT_STORE_CREATE_NEW_FLAG, hMsg);
}

extern BOOL WINAPI msgDecodeCallback(
    const void *pvArg,
    BYTE *pbData,
    DWORD cbData,
    BOOL fFinal);

extern BOOL WINAPI msgEncodeCallback(
    const void *pvArg,
    BYTE *pbData,
    DWORD cbData,
    BOOL fFinal);


static CMSG_STREAM_INFO *mkStreamInfo(void *pvArg, BOOL decode) {
	CMSG_STREAM_INFO *res = malloc(sizeof(CMSG_STREAM_INFO));
	memset(res, 0, sizeof(CMSG_STREAM_INFO));
	res->cbContent = CMSG_INDEFINITE_LENGTH;
	if (decode) {
		res->pfnStreamOutput = &msgDecodeCallback;
	} else {
		res->pfnStreamOutput = &msgEncodeCallback;
	}
	res->pvArg = pvArg;
	return res;
}

static CMSG_SIGNED_ENCODE_INFO *mkSignedInfo(int cSigners) {
	int i;

	CMSG_SIGNED_ENCODE_INFO *res = malloc(sizeof(CMSG_SIGNED_ENCODE_INFO));
	memset(res, 0, sizeof(CMSG_SIGNED_ENCODE_INFO));
	res->cbSize = sizeof(CMSG_SIGNED_ENCODE_INFO);

	res->cSigners = cSigners;
	res->rgSigners = (PCMSG_SIGNER_ENCODE_INFO) malloc(sizeof(CMSG_SIGNER_ENCODE_INFO) * cSigners);
	memset(res->rgSigners, 0, sizeof(CMSG_SIGNER_ENCODE_INFO) * cSigners);

	res->cCertEncoded = cSigners;
	res->rgCertEncoded =  malloc(sizeof(CERT_BLOB) * cSigners);
	memset(res->rgCertEncoded, 0, sizeof(CERT_BLOB) * cSigners);

	return res;
}

static void setSignedInfo(CMSG_SIGNED_ENCODE_INFO *out, int nSigner, HCRYPTPROV hCryptProv, PCCERT_CONTEXT pSignerCert, DWORD dwKeySpec, LPSTR oid) {
	out->rgSigners[nSigner].cbSize = sizeof(CMSG_SIGNER_ENCODE_INFO);
	out->rgSigners[nSigner].pCertInfo = pSignerCert->pCertInfo;
	out->rgSigners[nSigner].hCryptProv = hCryptProv;
	out->rgSigners[nSigner].dwKeySpec = dwKeySpec;
	out->rgSigners[nSigner].HashAlgorithm.pszObjId = oid;
	out->rgSigners[nSigner].pvHashAuxInfo = NULL;

	out->rgCertEncoded[nSigner].cbData = pSignerCert->cbCertEncoded;
	out->rgCertEncoded[nSigner].pbData = pSignerCert->pbCertEncoded;
}

static void freeSignedInfo(CMSG_SIGNED_ENCODE_INFO *info) {
	free(info->rgCertEncoded);
	free(info->rgSigners);
	free(info);
}
*/
import "C"

import (
	"encoding/asn1"
	"fmt"
	"io"
	"io/ioutil"
	"unsafe"

	"github.com/pkg/errors"
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
	lastError error
	data      unsafe.Pointer
	n, maxN   int
	eof       bool
}

// EncodeOptions specifies message creation details
type EncodeOptions struct {
	Detached bool                  // Signature is detached
	HashAlg  asn1.ObjectIdentifier // Signature hash algorithm ID
	Signers  []Cert                // Signing certificate list
}

// OpenToDecode creates new Msg in decode mode. If detachedSig parameter is specified,
// it must contain detached P7S signature
func OpenToDecode(src io.Reader, detachedSig ...[]byte) (res *Msg, rErr error) {
	var (
		flags C.DWORD
		si    *C.CMSG_STREAM_INFO
	)
	res = new(Msg)
	if len(detachedSig) > 0 {
		flags = C.CMSG_DETACHED_FLAG
		si = nil
	} else {
		si = C.mkStreamInfo(unsafe.Pointer(res), C.BOOL(1))
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
	return res, nil
}

func (msg *Msg) onDecode(pbData *C.BYTE, cbData C.DWORD, fFinal bool) bool {
	fmt.Println("on decode", int(cbData))
	if int(cbData) > msg.maxN {
		msg.lastError = fmt.Errorf("Buffer overrun on decoding")
		return false
	}
	C.memcpy(msg.data, unsafe.Pointer(pbData), C.size_t(cbData))
	msg.n = int(cbData)
	fmt.Println("decode", msg.n)
	return true
}

func (msg *Msg) onEncode(pbData *C.BYTE, cbData C.DWORD, fFinal bool) bool {
	msg.n, msg.lastError = msg.dest.Write(C.GoBytes(unsafe.Pointer(pbData), C.int(cbData)))
	fmt.Println("encode", msg.n)
	return msg.lastError == nil
}

// OpenToEncode creates new Msg in encode mode.
func OpenToEncode(dest io.Writer, options EncodeOptions) (res *Msg, rErr error) {
	var flags C.DWORD
	if len(options.Signers) == 0 {
		return nil, fmt.Errorf("Signer certificates list is empty")
	}
	if options.HashAlg == nil {
		options.HashAlg = GOST_R3411_12_256
	}
	if options.Detached {
		flags = C.CMSG_DETACHED_FLAG
	}
	res = new(Msg)
	si := C.mkStreamInfo(unsafe.Pointer(res), C.BOOL(0))
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
			return nil, getErr("Error acquiring certificate private key")
		}
		C.setSignedInfo(signedInfo, C.int(i), C.HCRYPTPROV(hCryptProv), signerCert.pCert, dwKeySpec, (*C.CHAR)(hashOID))
	}
	res.dest = dest
	res.hMsg = C.CryptMsgOpenToEncode(
		C.MY_ENC_TYPE,              // encoding type
		flags,                      // flags
		C.CMSG_SIGNED,              // message type
		unsafe.Pointer(signedInfo), // pointer to structure
		nil,                        // inner content OID
		si,                         // stream information
	)
	if res.hMsg == nil {
		return nil, getErr("Error opening message for encoding")
	}
	return res, nil
}

// Close needs to be called to release internal message handle
func (msg *Msg) Close() error {
	if msg.dest != nil {
		fmt.Println("###", msg.n)
		if !msg.update([]byte{0}, 0, true) {
			return getErr("Error finalizing message")
		}
	}
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
	fmt.Println("---", len(buf), n)
	return C.CryptMsgUpdate(msg.hMsg, (*C.BYTE)(unsafe.Pointer(&buf[0])), C.DWORD(n), lc) != 0
}

// Read parses message input stream and fills buf parameter with decoded data chunk
func (msg *Msg) Read(buf []byte) (int, error) {
	if msg.eof {
		return 0, io.EOF
	}
	nRead, err := msg.src.Read(buf)
	if err != nil && err != io.EOF {
		return nRead, err
	}
	msg.data = unsafe.Pointer(&buf[0])
	msg.n = 0
	msg.maxN = len(buf)
	msg.eof = (err == io.EOF)
	ok := msg.update(buf, nRead, msg.eof)
	if !ok {
		return 0, getErr("Error updating message body while reading")
	}
	return msg.n, msg.lastError
}

// Write encodes provided bytes into message output data stream
func (msg *Msg) Write(buf []byte) (n int, err error) {
	if ok := msg.update(buf, len(buf), false); !ok {
		return 0, getErr("Error updating message body while writing")
	}
	fmt.Println("***", msg.n)
	return len(buf), msg.lastError
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
