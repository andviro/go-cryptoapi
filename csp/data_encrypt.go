package csp

/*
#include "common.h"

typedef struct {
	CRYPT_ENCRYPT_MESSAGE_PARA params;
	DWORD cRecipients;
	PCCERT_CONTEXT *rgRecipientCerts;
} _ENCRYPT_DATA_PARAMS;

static _ENCRYPT_DATA_PARAMS *mkEncryptDataParams(HCRYPTPROV hCryptProv, int cRecipients) {
	_ENCRYPT_DATA_PARAMS *res = malloc(sizeof(_ENCRYPT_DATA_PARAMS));
	memset(res, 0, sizeof(_ENCRYPT_DATA_PARAMS));

	res->params.cbSize = sizeof(CMSG_ENVELOPED_ENCODE_INFO);
    res->params.dwMsgEncodingType = MY_ENC_TYPE;
	res->params.hCryptProv = hCryptProv;
	res->params.ContentEncryptionAlgorithm.pszObjId = (LPSTR)ENCRYPT_OID;

	res->cRecipients = (DWORD)cRecipients;
	res->rgRecipientCerts = malloc(sizeof(PCCERT_CONTEXT) * cRecipients);
	memset(res->rgRecipientCerts, 0, sizeof(PCCERT_CONTEXT) * cRecipients);
	return res;
}

static void freeEncryptDataParams(_ENCRYPT_DATA_PARAMS *params) {
	free(params->rgRecipientCerts);
	free(params);
}

static void setRecipientCert(_ENCRYPT_DATA_PARAMS *out, int nSigner, PCCERT_CONTEXT pRecipientCert) {
	out->rgRecipientCerts[nSigner] = pRecipientCert;
}

static CRYPT_DECRYPT_MESSAGE_PARA *mkDecryptMessagePara(HCERTSTORE *store) {
    CRYPT_DECRYPT_MESSAGE_PARA  *decryptParams = malloc(sizeof(CRYPT_DECRYPT_MESSAGE_PARA));
    memset(decryptParams, 0, sizeof(CRYPT_DECRYPT_MESSAGE_PARA));
    decryptParams->cbSize = sizeof(CRYPT_DECRYPT_MESSAGE_PARA);
    decryptParams->dwMsgAndCertEncodingType = MY_ENC_TYPE;
    decryptParams->cCertStore = 1;
    decryptParams->rghCertStore = store;
	return decryptParams;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// EncryptData encrypts arbitrary byte slice for one or more recipient
// certificates
func EncryptData(data []byte, options EncryptOptions) ([]byte, error) {
	if len(options.Receivers) == 0 {
		return nil, fmt.Errorf("Receivers certificates list is empty")
	}
	ctx, err := AcquireCtx("", "", ProvGost2012_512, CryptVerifyContext)
	if err != nil {
		return nil, err
	}
	edp := C.mkEncryptDataParams(ctx.hProv, C.int(len(options.Receivers)))
	defer C.freeEncryptDataParams(edp)

	for i, receiverCert := range options.Receivers {
		C.setRecipientCert(edp, C.int(i), receiverCert.pCert)
	}
	var slen C.DWORD
	var res []byte
	if C.CryptEncryptMessage(&edp.params, C.DWORD(edp.cRecipients), edp.rgRecipientCerts, (*C.BYTE)(&data[0]), C.DWORD(len(data)), nil, &slen) == 0 {
		return res, getErr("Error getting encrypted data size")
	}
	res = make([]byte, slen)
	if C.CryptEncryptMessage(&edp.params, C.DWORD(edp.cRecipients), edp.rgRecipientCerts, (*C.BYTE)(&data[0]), C.DWORD(len(data)), (*C.BYTE)(&res[0]), &slen) == 0 {
		return nil, getErr("Error getting encrypted data body")
	}
	return res, nil
}

// DecryptData decrypts byte slice using provided certificate store for private
// key lookup
func DecryptData(data []byte, store *CertStore) ([]byte, error) {
	pdp := C.mkDecryptMessagePara(&store.hStore)
	defer C.free(unsafe.Pointer(pdp))
	var slen C.DWORD
	if C.CryptDecryptMessage(pdp, (*C.BYTE)(&data[0]), C.DWORD(len(data)), nil, &slen, nil) == 0 {
		return nil, getErr("Error getting decrypted data size")
	}
	res := make([]byte, int(slen))
	if C.CryptDecryptMessage(pdp, (*C.BYTE)(&data[0]), C.DWORD(len(data)), (*C.BYTE)(&res[0]), &slen, nil) == 0 {
		return nil, getErr("Error getting decrypted data body")
	}
	return res, nil
}
