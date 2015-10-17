package csp

//#include "common.h"
import "C"

import (
	"unsafe"
)

// CertInfo encapsulates certificate properties
type CertInfo struct {
	pCertInfo C.PCERT_INFO
}

// Info extracts CertInfo from Cert
func (c *Cert) Info() CertInfo {
	return CertInfo{c.pCert.pCertInfo}
}

func decodeNameBlob(pNameBlob *C.CERT_NAME_BLOB) (string, error) {
	var slen C.DWORD

	flags := C.DWORD(C.CERT_X500_NAME_STR | C.CERT_NAME_STR_NO_PLUS_FLAG)

	slen = C.CertNameToStr(C.X509_ASN_ENCODING, pNameBlob, flags, nil, 0)
	buf := make([]byte, slen)
	slen = C.CertNameToStr(C.X509_ASN_ENCODING, pNameBlob, flags, (*C.CHAR)(unsafe.Pointer(&buf[0])), slen)
	if slen < 1 {
		return "", getErr("Error decoding name blob")
	}
	return string(buf[:slen-1]), nil
}

// Subject decodes certificate subject
func (ci *CertInfo) Subject() (string, error) {
	return decodeNameBlob(&ci.pCertInfo.Subject)
}

// MustSubject returns certificate name string or panics
func (ci *CertInfo) MustSubject() string {
	res, err := ci.Subject()
	if err != nil {
		panic(err)
	}
	return res
}

// Issuer decodes certificate issuer
func (ci *CertInfo) Issuer() (string, error) {
	return decodeNameBlob(&ci.pCertInfo.Issuer)
}

// MustIssuer returns certificate issuer or panics
func (ci *CertInfo) MustIssuer() string {
	res, err := ci.Issuer()
	if err != nil {
		panic(err)
	}
	return res
}
