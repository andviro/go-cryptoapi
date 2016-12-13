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
func (c Cert) Info() CertInfo {
	return CertInfo{c.pCert.pCertInfo}
}

// SignatureAlgorithm returns certificate signature algorithm as object ID
// string
func (ci CertInfo) SignatureAlgorithm() string {
	return C.GoString((*C.char)(unsafe.Pointer(ci.pCertInfo.SignatureAlgorithm.pszObjId)))
}

// SignatureAlgorithm returns certificate subject public key algorithm as
// object ID string
func (ci CertInfo) PublicKeyAlgorithm() string {
	return C.GoString((*C.char)(unsafe.Pointer(ci.pCertInfo.SubjectPublicKeyInfo.Algorithm.pszObjId)))
}

// SignatureAlgorithm returns certificate subject public key as byte slice
func (ci CertInfo) PublicKeyBytes() []byte {
	pb := ci.pCertInfo.SubjectPublicKeyInfo.PublicKey
	return C.GoBytes(unsafe.Pointer(pb.pbData), C.int(pb.cbData))
}

func nameToStr(src C.PCERT_NAME_BLOB) (string, error) {
	slen := C.CertNameToStr(C.X509_ASN_ENCODING, src, C.CERT_X500_NAME_STR, nil, 0)
	data := make([]byte, slen)
	if n := C.CertNameToStr(C.X509_ASN_ENCODING, src, C.CERT_X500_NAME_STR, (*C.CHAR)(unsafe.Pointer(&data[0])), slen); n == 0 {
		return string(data), getErr("Error converting RDN to string")
	}
	return string(data), nil
}

// SubjectStr returns certificate subject converted to Go string
func (ci CertInfo) SubjectStr() (string, error) {
	return nameToStr(&ci.pCertInfo.Subject)
}

// IssuerStr returns certificate issuer converted to Go string
func (ci CertInfo) IssuerStr() (string, error) {
	return nameToStr(&ci.pCertInfo.Issuer)
}
