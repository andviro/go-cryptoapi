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
