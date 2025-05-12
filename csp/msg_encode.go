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
		if C.CryptAcquireCertificatePrivateKey(signerCert.pCert, 0, nil, &hCryptProv, &dwKeySpec, nil) == 0 {
			return nil, getErr("Error acquiring certificate private key")
		}
		C.setSignedInfo(signedInfo, C.int(i), C.HCRYPTPROV(hCryptProv), signerCert.pCert, dwKeySpec, (*C.CHAR)(hashOID), cbool(!options.NoCert))
		res.signerKeys = append(res.signerKeys, hCryptProv)
	}
	res.hMsg = C.CryptMsgOpenToEncode(
		C.MY_ENC_TYPE,              // encoding type
		flags,                      // flags
		C.CMSG_SIGNED,              // message type
		unsafe.Pointer(signedInfo), // pointer to structure
		nil,                        // inner content OID
		streamInfo,                 // stream information
	)
	if res.hMsg == nil {
		return nil, getErr("Error opening message for encoding")
	}
	defer func() {
		if rErr == nil {
			return
		} else if err := res.cleanup(); err != nil {
			rErr = fmt.Errorf("Error closing msg: %v (original error: %v)", err, rErr)
		}
	}()
	return res, nil
}

// Write encodes provided bytes into message output data stream
func (msg *Msg) Write(buf []byte) (int, error) {
	if ok := msg.update(buf, len(buf), msg.lastError != nil); !ok {
		return 0, getErr("Error updating message body while writing")
	}
	return len(buf), msg.lastError
}

func (msg *Msg) cleanup() error {
	for _, hProv := range msg.signerKeys {
		if C.CryptReleaseContext(hProv, 0) == 0 {
			return getErr("Error releasing context")
		}
	}
	if C.CryptMsgClose(msg.hMsg) == 0 {
		return getErr("Error closing message")
	}
	return nil
}

// Close needs to be called to release internal message handle and flush
// underlying encoded message.
func (msg *Msg) Close() error {
	if err := msg.flush(); err != nil {
		return err
	}
	return msg.cleanup()
}
