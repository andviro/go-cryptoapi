package csp

/*
#include "common.h"

extern CMSG_STREAM_INFO *mkStreamInfo(void *pvArg);
*/
import "C"
import (
	"io"
	"unsafe"

	"errors"
)

type Decryptor struct {
	hMsg          C.HCRYPTMSG
	w             io.Writer
	callbackID    int64
	maxHeaderSize int
	lastError     error
	decrypting    bool
	store         *CertStore
}

// OpenToDecrypt creates new Msg in decrypt mode. Maximum header size, if
// non-zero, limits size of data read from message until envelope recipient
// info is available.
func OpenToDecrypt(dest io.Writer, store *CertStore, maxHeaderSize int) (msg *Decryptor, rErr error) {
	res := new(Decryptor)
	res.maxHeaderSize = maxHeaderSize
	res.store = store
	res.w = dest
	res.callbackID = registerCallback(res.onWrite)
	si := C.mkStreamInfo(unsafe.Pointer(&res.callbackID))
	defer C.free(unsafe.Pointer(si))
	res.hMsg = C.CryptMsgOpenToDecode(
		C.MY_ENC_TYPE, // encoding type
		0,             // flags
		0,             // message type (get from message)
		0,             // default cryptographic provider
		nil,           // recipient information
		si,            // stream info
	)
	if res.hMsg == nil {
		return nil, getErr("Error opening message for decrypting")
	}
	return res, nil

}

// Write encodes provided bytes into message output data stream
func (msg *Decryptor) Write(buf []byte) (int, error) {
	if ok := msg.update(buf, len(buf), msg.lastError != nil); !ok {
		return 0, getErr("Error updating message body while writing")
	}
	if msg.decrypting {
		return len(buf), msg.lastError
	}
	var cbData C.DWORD
	if 0 == C.CryptMsgGetParam(msg.hMsg, C.CMSG_ENVELOPE_ALGORITHM_PARAM, 0, nil, &cbData) {
		switch ErrorCode(C.GetLastError()) {
		case ErrStreamNotReady:
			return len(buf), msg.lastError
		default:
			return 0, getErr("Error acquiring message envelope algorithm")
		}
	}
	cbData = C.DWORD(C.sizeof_DWORD)
	var numRecipients C.DWORD
	if 0 == C.CryptMsgGetParam(msg.hMsg, C.CMSG_RECIPIENT_COUNT_PARAM, 0, unsafe.Pointer(&numRecipients), &cbData) {
		return 0, getErr("Error acquiring message recipient count")
	}
	for i := 0; i < int(numRecipients); i++ {
		cert, err := msg.getRecipientCert(i, msg.store)
		if err != nil {
			return 0, err
		} else if cert == nil {
			continue
		}
		ctx, err := cert.Context()
		if err != nil {
			return 0, err
		}
		return msg.proceed(i, len(buf), ctx)
	}
	return 0, errors.New("no recipients found")
}

func (msg *Decryptor) proceed(i int, n int, ctx *Ctx) (int, error) {
	var decrPara C.CMSG_CTRL_DECRYPT_PARA
	decrPara.cbSize = C.sizeof_CMSG_CTRL_DECRYPT_PARA
	decrPara.hCryptProv = ctx.hProv
	decrPara.dwKeySpec = C.AT_KEYEXCHANGE
	decrPara.dwRecipientIndex = C.DWORD(i)
	if 0 == C.CryptMsgControl(msg.hMsg, 0, C.CMSG_CTRL_DECRYPT, unsafe.Pointer(&decrPara)) {
		if C.GetLastError() != 0 {
			return 0, getErr("Error setting decrypt parameter")
		}
	}
	return n, msg.lastError
}

func (msg *Decryptor) getRecipientCert(i int, store *CertStore) (*Cert, error) {
	var cbData C.DWORD
	if 0 == C.CryptMsgGetParam(msg.hMsg, C.CMSG_RECIPIENT_INFO_PARAM, C.DWORD(i), nil, &cbData) {
		return nil, getErr("Error acquiring message recipient info length")
	}
	recipientInfo := C.malloc(C.size_t(cbData))
	defer C.free(recipientInfo)
	if 0 == C.CryptMsgGetParam(msg.hMsg, C.CMSG_RECIPIENT_INFO_PARAM, C.DWORD(i), recipientInfo, &cbData) {
		return nil, getErr("Error acquiring message recipient info")
	}

	if pCert := C.CertGetSubjectCertificateFromStore(store.hStore, C.MY_ENC_TYPE, C.PCERT_INFO(recipientInfo)); pCert != nil {
		return &Cert{pCert: pCert}, nil
	}
	if ErrorCode(C.GetLastError()) != ErrCryptNotFound {
		return nil, getErr("Error getting certificate from store")
	}
	return nil, nil
}

func (msg *Decryptor) onWrite(pbData *C.BYTE, cbData C.DWORD, fFinal bool) bool {
	if _, err := msg.w.Write(C.GoBytes(unsafe.Pointer(pbData), C.int(cbData))); err != nil {
		msg.lastError = err
	}
	return msg.lastError == nil
}

func (msg *Decryptor) update(buf []byte, n int, lastCall bool) bool {
	var lc C.BOOL
	if lastCall {
		lc = C.BOOL(1)
	}
	return C.CryptMsgUpdate(msg.hMsg, (*C.BYTE)(unsafe.Pointer(&buf[0])), C.DWORD(n), lc) != 0
}
