package csp

/*
#include "common.h"

extern CMSG_STREAM_INFO *mkStreamInfo(void *pvArg, BOOL decode);

static CMSG_ENVELOPED_ENCODE_INFO *mkEnvelopedInfo(HCRYPTPROV hCryptProv, int cRecipients) {
    CRYPT_ALGORITHM_IDENTIFIER EncryptAlgorithm;
    memset(&EncryptAlgorithm, 0, sizeof(CRYPT_ALGORITHM_IDENTIFIER));
    EncryptAlgorithm.pszObjId = (LPSTR)ENCRYPT_OID;

	CMSG_ENVELOPED_ENCODE_INFO *res = malloc(sizeof(CMSG_ENVELOPED_ENCODE_INFO));
	memset(res, 0, sizeof(CMSG_ENVELOPED_ENCODE_INFO));
	res->cbSize = sizeof(CMSG_ENVELOPED_ENCODE_INFO);
	res->hCryptProv = hCryptProv;
	res->ContentEncryptionAlgorithm = EncryptAlgorithm;
	res->pvEncryptionAuxInfo = NULL;
	res->cRecipients = cRecipients;
	res->rgpRecipients = malloc(sizeof(PCERT_INFO) * cRecipients);
	memset(res->rgpRecipients, 0, sizeof(PCERT_INFO) * cRecipients);
	return res;
}

static void freeEnvelopedInfo(CMSG_ENVELOPED_ENCODE_INFO *info) {
	free(info->rgpRecipients);
	free(info);
}

static void setRecipientInfo(CMSG_ENVELOPED_ENCODE_INFO *out, int nSigner, PCCERT_CONTEXT pRecipientCert) {
	out->rgpRecipients[nSigner] = pRecipientCert->pCertInfo;
}

*/
import "C"
import (
	"fmt"
	"io"
	"unsafe"

	"github.com/pkg/errors"
)

// EncryptOptions specifies message encryption details
type EncryptOptions struct {
	Receivers []Cert // Receiving certificate list
}

// OpenToEncrypt creates new Msg in encrypt mode.
func OpenToEncrypt(dest io.Writer, options EncryptOptions) (*Msg, error) {
	res := new(Msg)
	if len(options.Receivers) == 0 {
		return nil, fmt.Errorf("Receivers certificates list is empty")
	}
	ctx, err := AcquireCtx("", "", ProvGost2012, CryptVerifyContext)
	if err != nil {
		return nil, err
	}

	si := C.mkStreamInfo(unsafe.Pointer(res), C.BOOL(0))
	defer C.free(unsafe.Pointer(si))

	envelopedInfo := C.mkEnvelopedInfo(ctx.hProv, C.int(len(options.Receivers)))
	defer C.freeEnvelopedInfo(envelopedInfo)

	for i, receiverCert := range options.Receivers {
		C.setRecipientInfo(envelopedInfo, C.int(i), receiverCert.pCert)
	}
	res.dest = dest
	res.hMsg = C.CryptMsgOpenToEncode(
		C.MY_ENC_TYPE,                 // encoding type
		0,                             // flags
		C.CMSG_ENVELOPED,              // message type
		unsafe.Pointer(envelopedInfo), // pointer to structure
		nil,                           // inner content OID
		si,                            // stream information
	)
	if res.hMsg == nil {
		return nil, getErr("Error opening message for encoding")
	}
	return res, nil
}

// OpenToDecrypt creates new Msg in decrypt mode. Maximum header size, if
// non-zero, limits size of data read from message until envelope recipient
// info is available.
func OpenToDecrypt(src io.Reader, store *CertStore, maxHeaderSize int) (res *Msg, rErr error) {
	si := C.mkStreamInfo(unsafe.Pointer(res), C.BOOL(1))
	defer C.free(unsafe.Pointer(si))
	hMsg := C.CryptMsgOpenToDecode(
		C.MY_ENC_TYPE, // encoding type
		0,             // flags
		0,             // message type (get from message)
		0,             // default cryptographic provider
		nil,           // recipient information
		si,            // stream info
	)
	if hMsg == nil {
		return nil, getErr("Error opening message for decrypting")
	}
	defer func() {
		if rErr == nil {
			return
		}
		if C.CryptMsgClose(hMsg) == 0 {
			rErr = errors.Errorf("%v (original error: %v)", getErr("Error closing message"), rErr)
		}
	}()
	res = &Msg{hMsg: hMsg, src: src}
	buf := make([]byte, 1024)
	var algID C.CRYPT_ALGORITHM_IDENTIFIER
	var cbData C.DWORD = C.sizeof_CRYPT_ALGORITHM_IDENTIFIER
	for n := 0; maxHeaderSize == 0 || n < maxHeaderSize; n += len(buf) {
		nRead, err := src.Read(buf)
		if err != nil {
			return nil, err
		}
		fmt.Println("read ", nRead)
		if !res.update(buf, nRead, false) {
			return nil, getErr("Error updating message header")
		}
		if 0 == C.CryptMsgGetParam(res.hMsg, C.CMSG_ENVELOPE_ALGORITHM_PARAM, 0, unsafe.Pointer(&algID), &cbData) {
			if ErrorCode(C.GetLastError()) != ErrStreamNotReady {
				return nil, getErr("Error acquiring message envelope algorithm")
			}
			continue
		}
		break
	}
	fmt.Println("alg ID", algID)
	cbData = C.sizeof_DWORD
	var numRecipients C.DWORD
	if 0 == C.CryptMsgGetParam(res.hMsg, C.CMSG_RECIPIENT_COUNT_PARAM, 0, unsafe.Pointer(&numRecipients), &cbData) {
		return nil, getErr("Error acquiring message envelope algorithm")
	}
	fmt.Println("num recipients", numRecipients)
	for i := 0; i < int(numRecipients); i++ {
		var recipientInfo C.CERT_INFO
		if 0 == C.CryptMsgGetParam(res.hMsg, C.CMSG_RECIPIENT_INFO_PARAM, C.DWORD(i), unsafe.Pointer(&recipientInfo), &cbData) {
			return nil, getErr("Error acquiring message recipient info")
		}
		pCert := C.CertGetSubjectCertificateFromStore(store.hStore, C.MY_ENC_TYPE, C.PCERT_INFO(unsafe.Pointer(&recipientInfo)))
		if pCert == nil {
			if ErrorCode(C.GetLastError()) != ErrCryptNotFound {
				return nil, getErr("Error getting certificate from store")
			}
			continue
		}
		var provInfo C.CRYPT_KEY_PROV_INFO
		cbData = C.sizeof_CRYPT_KEY_PROV_INFO
		if 0 == C.CertGetCertificateContextProperty(pCert, C.CERT_KEY_PROV_INFO_PROP_ID, unsafe.Pointer(&provInfo), &cbData) {
			return nil, getErr("Error getting certificate context property")
		}
		fmt.Println("prov ", provInfo)
		var hProv C.HCRYPTPROV
		if C.CryptAcquireContextW(&hProv, provInfo.pwszContainerName, provInfo.pwszProvName, provInfo.dwProvType, provInfo.dwFlags) == 0 {
			return nil, getErr("Error acquiring context")
		}
		var decrPara C.CMSG_CTRL_DECRYPT_PARA
		decrPara.cbSize = C.sizeof_CMSG_CTRL_DECRYPT_PARA
		decrPara.hCryptProv = hProv
		decrPara.dwKeySpec = provInfo.dwKeySpec
		decrPara.dwRecipientIndex = C.DWORD(i)
		if 0 == C.CryptMsgControl(res.hMsg, 0, C.CMSG_CTRL_DECRYPT, unsafe.Pointer(&decrPara)) {
			return nil, getErr("Error setting decrypt parameter")
		}
		return res, nil
	}
	return nil, errors.New("no recipients found")
}
