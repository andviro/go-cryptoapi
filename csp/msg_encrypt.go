package csp

/*
#include "common.h"

static CMSG_ENVELOPED_ENCODE_INFO *mkEnvelopedInfo(HCRYPTPROV hCryptProv, int cRecipients) {
    CRYPT_ALGORITHM_IDENTIFIER *EncryptAlgorithm = malloc(sizeof(CRYPT_ALGORITHM_IDENTIFIER));
    memset(&EncryptAlgorithm, 0, sizeof(CRYPT_ALGORITHM_IDENTIFIER));
    EncryptAlgorithm.pszObjId = (LPSTR)ENCRYPT_OID;

	CMSG_ENVELOPED_ENCODE_INFO *res = malloc(sizeof(CMSG_ENVELOPED_ENCODE_INFO));
	memset(&res, 0, sizeof(CMSG_ENVELOPED_ENCODE_INFO));
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
	free(info->rgSigners);
	free(info);
}
*/
import "C"

import (
	"fmt"
	"io"
	"unsafe"
)

// EncryptOptions specifies message encryption details
type EncryptOptions struct {
	Receivers []Cert // Receiving certificate list
}

// OpenToEncrypt creates new Msg in encrypt mode.
func OpenToEncrypt(dest io.Writer, options EncryptOptions) (*Msg, error) {
	var flags C.DWORD

	res := new(Msg)

	if len(options.Receivers) == 0 {
		return fmt.Errorf("Receivers certificates list is empty")
	}
	ctx, err := AcquireCtx("", "", "", CryptVerifyContext)
	if err != nil {
		return err
	}

	si := C.mkStreamInfo(unsafe.Pointer(res), C.BOOL(0))
	defer C.free(unsafe.Pointer(si))

	envelopedInfo := C.mkEnvelopedInfo(ctx.hProv, int(len(options.Receivers)))
	defer C.freeEnvelopedInfo(envelopedInfo)

	for _, receiverCert := range options.Receivers {
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
