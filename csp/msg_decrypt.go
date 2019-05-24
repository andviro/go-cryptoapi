package csp

/*
#include "common.h"

extern CMSG_STREAM_INFO *mkStreamInfo(void *pvArg);
*/
import "C"
import (
	"fmt"
	"io"
	"unsafe"

	"github.com/pkg/errors"
)

// OpenToDecrypt creates new Msg in decrypt mode. Maximum header size, if
// non-zero, limits size of data read from message until envelope recipient
// info is available.
func OpenToDecrypt(src io.Reader, store *CertStore, maxHeaderSize int) (msg *Msg, rErr error) {
	res := new(Msg)
	res.callbackID = registerCallback(res.onUpdate)
	si := C.mkStreamInfo(unsafe.Pointer(&res.callbackID))
	defer C.free(unsafe.Pointer(si))
	res.src = src
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
	defer func() {
		if rErr == nil {
			return
		}
		if C.CryptMsgClose(res.hMsg) == 0 {
			rErr = errors.Errorf("%v (original error: %v)", getErr("Error closing message"), rErr)
		}
	}()
	buf := make([]byte, 1024)
	var cbData C.DWORD
	for n := 0; maxHeaderSize == 0 || n < maxHeaderSize; n += len(buf) {
		nRead, err := src.Read(buf)
		if err != nil {
			return nil, err
		}
		if !res.update(buf, nRead, false) {
			return nil, getErr("Error updating message header")
		}
		if 0 == C.CryptMsgGetParam(res.hMsg, C.CMSG_ENVELOPE_ALGORITHM_PARAM, 0, nil, &cbData) {
			switch ErrorCode(C.GetLastError()) {
			case ErrStreamNotReady:
				continue
			default:
				return nil, getErr("Error acquiring message envelope algorithm")
			}
		}
		break
	}
	fmt.Println("msg ready")
	cbData = C.sizeof_DWORD
	var numRecipients C.DWORD
	if 0 == C.CryptMsgGetParam(res.hMsg, C.CMSG_RECIPIENT_COUNT_PARAM, 0, unsafe.Pointer(&numRecipients), &cbData) {
		return nil, getErr("Error acquiring message recipient count")
	}
	for i := 0; i < int(numRecipients); i++ {
		fmt.Println("recipient", i)
		cert, err := res.getRecipientCert(i, store)
		if err != nil {
			return nil, err
		} else if cert == nil {
			continue
		}
		ctx, err := cert.Context()
		if err != nil {
			return nil, err
		}
		return proceed(res, src, i, ctx)
	}
	return nil, errors.New("no recipients found")
}

func proceed(res *Msg, src io.Reader, i int, ctx *Ctx) (*Msg, error) {
	pr, pw := io.Pipe()
	res.src, res.dest = pr, pw
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := src.Read(buf)
			fmt.Println("read", n, err)
			if err != nil && err != io.EOF {
				pw.CloseWithError(err)
				return
			}
			if ok := res.update(buf, n, err == io.EOF); !ok {
				pw.CloseWithError(getErr("Error updating message body while writing"))
				return
			}
			if err == io.EOF {
				fmt.Println("eof", err)
				pw.CloseWithError(err)
				return
			}
		}
	}()
	var decrPara C.CMSG_CTRL_DECRYPT_PARA
	decrPara.cbSize = C.sizeof_CMSG_CTRL_DECRYPT_PARA
	decrPara.hCryptProv = ctx.hProv
	decrPara.dwKeySpec = C.AT_KEYEXCHANGE
	decrPara.dwRecipientIndex = C.DWORD(i)
	if 0 == C.CryptMsgControl(res.hMsg, 0, C.CMSG_CTRL_DECRYPT, unsafe.Pointer(&decrPara)) {
		if C.GetLastError() != 0 {
			return nil, getErr("Error setting decrypt parameter")
		}
	}
	return res, nil
}

func (msg *Msg) getRecipientCert(i int, store *CertStore) (*Cert, error) {
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
