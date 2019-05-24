package csp

/*
#include "common.h"

extern CMSG_STREAM_INFO *mkStreamInfo(void *pvArg);

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
	"unsafe"

	"github.com/pkg/errors"
)

// EncodeOptions specifies message creation details
type EncodeOptions struct {
	Detached bool                  // Signature is detached
	HashAlg  asn1.ObjectIdentifier // Signature hash algorithm ID
	Signers  []Cert                // Signing certificate list
}

// OpenToEncode creates new Msg in encode mode.
func OpenToEncode(dest io.Writer, options EncodeOptions) (msg *Msg, rErr error) {
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
	res := &Msg{dest: dest}
	res.callbackID = registerCallback(res.onUpdate)
	si := C.mkStreamInfo(unsafe.Pointer(&res.callbackID))
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
	defer func() {
		if rErr == nil {
			return
		}
		if C.CryptMsgClose(res.hMsg) == 0 {
			rErr = errors.Errorf("%v (original error: %v)", getErr("Error closing message"), rErr)
		}
	}()
	return res, nil
}

// Write encodes provided bytes into message output data stream
func (msg *Msg) Write(buf []byte) (int, error) {
	fmt.Println("write", len(buf))
	if ok := msg.update(buf, len(buf), false); !ok {
		return 0, getErr("Error updating message body while writing")
	}
	return len(buf), msg.lastError
}

// Close needs to be called to release internal message handle and flush
// underlying encoded message.
func (msg *Msg) Close() error {
	if msg.src == nil {
		if !msg.update([]byte{0}, 0, true) {
			return getErr("Error finalizing message")
		}
	}
	if C.CryptMsgClose(msg.hMsg) == 0 {
		return getErr("Error closing message")
	}
	return msg.lastError
}
