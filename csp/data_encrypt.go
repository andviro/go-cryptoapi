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
func EncryptData(data []byte, options EncryptOptions) (_ []byte, rErr error) {
	if len(options.Receivers) == 0 {
		return nil, fmt.Errorf("Receivers certificates list is empty")
	}
	ctx, err := AcquireCtx("", "", ProvGost2012_512, CryptVerifyContext)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := ctx.Close(); err != nil {
			rErr = fmt.Errorf("Encrypting data: %v (original error: %v)", err, rErr)
		}
	}()
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

type BlockEncryptedData struct {
	IV               []byte
	CipherText       []byte
	SessionKey       SessionKey
	SessionPublicKey []byte
	KeyExp           C.DWORD
	DHParamsOID      string
	DigestOID        string
	PublicKeyOID     string
}

type BlockEncryptOptions struct {
	Receiver Cert
	KeyAlg   C.ALG_ID // If not set, C.CALG_DH_GR3410_12_256_EPHEM is used
	KeyExp   C.DWORD  // If not set, C.CALG_PRO_EXPORT is used
}

const publicKeyLength = 64

func BlockEncrypt(opts BlockEncryptOptions, data []byte) (BlockEncryptedData, error) {
	res := BlockEncryptedData{
		KeyExp: opts.KeyExp,
	}
	if opts.Receiver.IsZero() {
		return res, fmt.Errorf("receiver certificate not specified")
	}
	var provType ProvType
	switch opts.Receiver.Info().PublicKeyAlgorithm() {
	case GOSTR341012256:
		provType = ProvGost2012
	default:
		provType = ProvGost2012_512
	}
	if opts.KeyExp == 0 {
		opts.KeyExp = C.CALG_PRO_EXPORT
	}
	if opts.KeyAlg == 0 {
		if provType == ProvGost2012 {
			opts.KeyAlg = C.CALG_DH_GR3410_12_256_EPHEM
		} else {
			opts.KeyAlg = C.CALG_DH_GR3410_12_512_EPHEM
		}
	}
	var (
		ctx Ctx
		err error
	)
	ctx, err = AcquireCtx("", "", provType, CryptVerifyContext)
	if err != nil {
		return res, err
	}
	defer ctx.Close()
	pubKey, err := ctx.ImportPublicKeyInfo(opts.Receiver)
	if err != nil {
		return res, err
	}
	defer pubKey.Close()
	keyData, err := pubKey.Encode(nil)
	if err != nil {
		return res, err
	}
	// keyOID, err := pubKey.GetOID()
	// if err != nil {
	// 	return res, fmt.Errorf("getting receiver's key public key algorithm OID: %w", err)
	// }
	// res.PublicKeyOID = keyOID
	res.PublicKeyOID = "1.2.643.7.1.1.1.2"
	dhoid, err := pubKey.GetDHOID()
	if err != nil {
		return res, fmt.Errorf("getting receiver's key DH: %w", err)
	}
	res.DHParamsOID = dhoid
	digestOID, err := pubKey.GetHashOID()
	if err != nil {
		return res, fmt.Errorf("getting receiver's key hash alg ID: %w", err)
	}
	res.DigestOID = digestOID
	if err := ctx.SetDHOID(dhoid); err != nil {
		return res, fmt.Errorf("setting context DH OID: %w", err)
	}
	ephemKey, err := ctx.GenKey(KeyPairID(opts.KeyAlg), C.CRYPT_EXPORTABLE)
	if err != nil {
		return res, fmt.Errorf("generating ephemeral key: %w", err)
	}
	defer ephemKey.Close()
	res.SessionPublicKey, err = ephemKey.Encode(nil)
	if err != nil {
		return res, fmt.Errorf("encoding ephemeral key: %w", err)
	}
	res.SessionPublicKey = res.SessionPublicKey[len(res.SessionPublicKey)-publicKeyLength:]
	agreeKey, err := ctx.ImportKey(keyData, &ephemKey)
	if err != nil {
		return res, fmt.Errorf("importing session public key: %w", err)
	}
	defer agreeKey.Close()
	if err := agreeKey.SetAlgID(opts.KeyExp); err != nil {
		return res, fmt.Errorf("setting algorithm ID to agree key: %w", err)
	}
	sessionKey, err := ctx.GenKey(C.CALG_G28147, C.CRYPT_EXPORTABLE)
	if err != nil {
		return res, fmt.Errorf("generating session key: %w", err)
	}
	defer sessionKey.Close()
	sessKey, err := sessionKey.Encode(&agreeKey)
	if err != nil {
		return res, fmt.Errorf("encoding session key: %w", err)
	}
	if res.SessionKey, err = sessKey.ToSessionKey(); err != nil {
		return res, fmt.Errorf("exporting session key: %w", err)
	}
	if err := sessionKey.SetMode(C.CRYPT_MODE_CBC); err != nil {
		return res, fmt.Errorf("setting session key mode CBC: %w", err)
	}
	if err := sessionKey.SetPadding(C.ISO10126_PADDING); err != nil {
		return res, fmt.Errorf("setting session key padding: %w", err)
	}
	res.IV, err = sessionKey.GetParam(C.KP_IV)
	if err != nil {
		return res, fmt.Errorf("getting session key IV: %w", err)
	}
	res.CipherText, err = sessionKey.Encrypt(data, nil)
	if err != nil {
		return res, fmt.Errorf("encrypting ciphertext: %w", err)
	}
	return res, nil
}

func BlockDecrypt(recipient Cert, data BlockEncryptedData) ([]byte, error) {
	ctx, err := recipient.Context()
	if err != nil {
		return nil, fmt.Errorf("getting recipient certificate context: %w", err)
	}
	defer ctx.Close()
	userKey, err := ctx.Key(C.AT_KEYEXCHANGE)
	if err != nil {
		return nil, fmt.Errorf("getting user key: %+v", err)
	}
	defer userKey.Close()
	if data.KeyExp == 0 {
		data.KeyExp = C.CALG_PRO_EXPORT
	}
	graftedPublicKey, err := userKey.Encode(nil)
	if err != nil {
		return nil, fmt.Errorf("encoding user key: %+v", err)
	}
	// HAHAHAHACKY
	copy(graftedPublicKey[len(graftedPublicKey)-publicKeyLength:], data.SessionPublicKey)
	agreeKey, err := ctx.ImportKey(graftedPublicKey, &userKey)
	if err != nil {
		return nil, fmt.Errorf("importing agree key: %+v", err)
	}
	defer agreeKey.Close()
	if err = agreeKey.SetAlgID(data.KeyExp); err != nil {
		return nil, fmt.Errorf("setting algorithm ID to agree key: %+v", err)
	}
	sb := data.SessionKey.ToSimpleBlob()
	sessionKey, err := ctx.ImportKey(sb, &agreeKey)
	if err != nil {
		return nil, fmt.Errorf("importing session key: %+v", err)
	}
	defer sessionKey.Close()
	if err := sessionKey.SetIV(data.IV); err != nil {
		return nil, fmt.Errorf("setting session key IV: %+v", err)
	}
	if err := sessionKey.SetMode(C.CRYPT_MODE_CBC); err != nil {
		return nil, fmt.Errorf("setting session key CBC mode: %+v", err)
	}
	if err := sessionKey.SetPadding(C.ISO10126_PADDING); err != nil {
		return nil, fmt.Errorf("setting session key padding: %+v", err)
	}
	return sessionKey.Decrypt(data.CipherText, nil)
}
