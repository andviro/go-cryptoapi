package csp

/*
#include "common.h"

extern CMSG_STREAM_INFO *mkStreamInfo(void *pvArg);

static CMSG_SIGNED_ENCODE_INFO *mkSignedInfo(int cSigners, BOOL includeCert) {
	int i;

	CMSG_SIGNED_ENCODE_INFO *res = malloc(sizeof(CMSG_SIGNED_ENCODE_INFO));
	memset(res, 0, sizeof(CMSG_SIGNED_ENCODE_INFO));
	res->cbSize = sizeof(CMSG_SIGNED_ENCODE_INFO);

	res->cSigners = cSigners;
	res->rgSigners = (PCMSG_SIGNER_ENCODE_INFO) malloc(sizeof(CMSG_SIGNER_ENCODE_INFO) * cSigners);
	memset(res->rgSigners, 0, sizeof(CMSG_SIGNER_ENCODE_INFO) * cSigners);

	if (includeCert) {
		res->cCertEncoded = cSigners;
		res->rgCertEncoded =  malloc(sizeof(CERT_BLOB) * cSigners);
		memset(res->rgCertEncoded, 0, sizeof(CERT_BLOB) * cSigners);
	} else {
		res->cCertEncoded = 0;
		res->rgCertEncoded = NULL;
	}

	return res;
}

static void setSignedInfo(CMSG_SIGNED_ENCODE_INFO *out, int nSigner, HCRYPTPROV hCryptProv, PCCERT_CONTEXT pSignerCert, DWORD dwKeySpec, LPSTR oid, BOOL includeCert) {
	out->rgSigners[nSigner].cbSize = sizeof(CMSG_SIGNER_ENCODE_INFO);
	out->rgSigners[nSigner].pCertInfo = pSignerCert->pCertInfo;
	out->rgSigners[nSigner].hCryptProv = hCryptProv;
	out->rgSigners[nSigner].dwKeySpec = dwKeySpec;
	out->rgSigners[nSigner].HashAlgorithm.pszObjId = oid;
	out->rgSigners[nSigner].pvHashAuxInfo = NULL;
	if (includeCert) {
		out->rgCertEncoded[nSigner].cbData = pSignerCert->cbCertEncoded;
		out->rgCertEncoded[nSigner].pbData = pSignerCert->pbCertEncoded;
	}
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
	"errors"
	"fmt"
	"io"
	"unsafe"
)

// EncodeOptions specifies message creation details
type EncodeOptions struct {
	Detached bool                  // Signature is detached
	HashAlg  asn1.ObjectIdentifier // Signature hash algorithm ID
	Signers  []Cert                // Signing certificate list
	NoCert   bool                  // Do not put certificate in result if true
}

func cbool(x bool) C.BOOL {
	if x {
		return C.BOOL(1)
	}
	return C.BOOL(0)
}

// OpenToEncode creates new Msg in encode mode.
func OpenToEncode(dest io.Writer, options EncodeOptions) (msg *Msg, rErr error) {
	var flags C.DWORD
	if len(options.Signers) == 0 {
		return nil, fmt.Errorf("signer certificates list is empty")
	}
	if options.HashAlg == nil {
		options.HashAlg = GOST_R3411_12_256
	}
	if options.Detached {
		flags = C.CMSG_DETACHED_FLAG
	}
	res := &Msg{w: dest}
	res.callbackID = registerCallback(res.onWrite)
	streamInfo := C.mkStreamInfo(unsafe.Pointer(&res.callbackID))
	defer C.free(unsafe.Pointer(streamInfo))
	signedInfo := C.mkSignedInfo(C.int(len(options.Signers)), cbool(!options.NoCert))
	defer C.freeSignedInfo(signedInfo)
	hashOID := C.CString(options.HashAlg.String())
	defer C.free(unsafe.Pointer(hashOID))
	for i, signerCert := range options.Signers {
		var (
			hCryptProv C.HCRYPTPROV_OR_NCRYPT_KEY_HANDLE
			dwKeySpec  C.DWORD
		)
		if err := expectError(func() bool {
			return C.CryptAcquireCertificatePrivateKey(signerCert.pCert, 0, nil, &hCryptProv, &dwKeySpec, nil) != 0
		}, "acquiring certificate private key"); err != nil {
			return nil, err
		}
		C.setSignedInfo(signedInfo, C.int(i), C.HCRYPTPROV(hCryptProv), signerCert.pCert, dwKeySpec, (*C.CHAR)(hashOID), cbool(!options.NoCert))
		res.signerKeys = append(res.signerKeys, hCryptProv)
	}
	return res, expectError(func() bool {
		res.hMsg = C.CryptMsgOpenToEncode(
			C.MY_ENC_TYPE,              // encoding type
			flags,                      // flags
			C.CMSG_SIGNED,              // message type
			unsafe.Pointer(signedInfo), // pointer to structure
			nil,                        // inner content OID
			streamInfo,                 // stream information
		)
		return res.hMsg != nil
	}, "opening message for encoding")
}

// Write encodes provided bytes into message output data stream
func (msg *Msg) Write(buf []byte) (int, error) {
	if err := expectError(func() bool {
		return msg.update(buf, len(buf), msg.lastError != nil)
	}, "updating message body while writing"); err != nil {
		return 0, err
	}
	return len(buf), msg.lastError
}

func (msg *Msg) cleanup() error {
	var res error
	for i, hProv := range msg.signerKeys {
		if err := expectErrorf(func() bool {
			return C.CryptReleaseContext(hProv, 0) != 0
		}, "releasing %d-th signer key context", i); err != nil {
			res = errors.Join(res, err)
		}
	}
	if err := expectError(func() bool {
		return msg.hMsg == nil || C.CryptMsgClose(msg.hMsg) != 0
	}, "closing message"); err != nil {
		res = errors.Join(res, err)
	}
	unregisterCallback(msg.callbackID)
	return res
}

// Close needs to be called to release internal message handle and flush
// underlying encoded message.
func (msg *Msg) Close() error {
	return errors.Join(msg.flush(), msg.cleanup())
}
