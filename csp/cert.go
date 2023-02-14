package csp

//#include "common.h"
import "C"

import (
	"encoding/hex"
	"unsafe"
)

// Cert encapsulates certificate context
type Cert struct {
	pCert C.PCCERT_CONTEXT
}

// IsZero returns true if certificate struct was not initialized
func (c Cert) IsZero() bool {
	return c.pCert == nil
}

// ParseCert creates certificate context from byte slice
func ParseCert(buf []byte) (res Cert, err error) {
	bufBytes := C.CBytes(buf)
	defer C.free(bufBytes)

	res.pCert = C.CertCreateCertificateContext(C.MY_ENC_TYPE, (*C.BYTE)(bufBytes), C.DWORD(len(buf)))
	if res.pCert == nil {
		err = getErr("Error creating certficate context")
		return
	}
	return
}

// Close releases certificate context
func (c Cert) Close() error {
	if C.CertFreeCertificateContext(c.pCert) == 0 {
		return getErr("Error releasing certificate context")
	}
	return nil
}

// CertPropertyID corresponds to a C type of DWORD
type CertPropertyID C.DWORD

// Constants for certificate property IDs
const (
	CertHashProp          CertPropertyID = C.CERT_HASH_PROP_ID
	CertKeyIDentifierProp CertPropertyID = C.CERT_KEY_IDENTIFIER_PROP_ID
	CertProvInfoProp      CertPropertyID = C.CERT_KEY_PROV_INFO_PROP_ID
)

// GetProperty is a base function for extracting certificate context properties
func (c Cert) GetProperty(propID CertPropertyID) ([]byte, error) {
	var slen C.DWORD
	var res []byte
	if C.CertGetCertificateContextProperty(c.pCert, C.DWORD(propID), nil, &slen) == 0 {
		return res, getErr("Error getting cert context property size")
	}
	res = make([]byte, slen)
	if C.CertGetCertificateContextProperty(c.pCert, C.DWORD(propID), unsafe.Pointer(&res[0]), &slen) == 0 {
		return res, getErr("Error getting cert context property body")
	}
	return res, nil
}

// ThumbPrint returns certificate's hash as a hexadecimal string
func (c Cert) ThumbPrint() (string, error) {
	thumb, err := c.GetProperty(CertHashProp)
	return hex.EncodeToString(thumb), err
}

// MustThumbPrint returns certificate's hash as a hexadecimal string or panics
func (c Cert) MustThumbPrint() string {
	if thumb, err := c.ThumbPrint(); err != nil {
		panic(err)
	} else {
		return thumb
	}
}

// SubjectID returns certificate's subject public key ID as a hexadecimal string
func (c Cert) SubjectID() (string, error) {
	thumb, err := c.GetProperty(CertKeyIDentifierProp)
	return hex.EncodeToString(thumb), err
}

// MustSubjectID returns certificate's subject id or panics
func (c Cert) MustSubjectID() string {
	if subj, err := c.SubjectID(); err != nil {
		panic(err)
	} else {
		return subj
	}
}

// Bytes returns encoded certificate as byte slice
func (c Cert) Bytes() []byte {
	return C.GoBytes(unsafe.Pointer(c.pCert.pbCertEncoded), C.int(c.pCert.cbCertEncoded))
}

// Context returns cryptographic context associated with the certificate
func (c Cert) Context() (Ctx, error) {
	var provInfo *C.CRYPT_KEY_PROV_INFO
	var res Ctx
	var cbData C.DWORD
	if C.CertGetCertificateContextProperty(c.pCert, C.CERT_KEY_PROV_INFO_PROP_ID, nil, &cbData) == 0 {
		return res, getErr("Error getting certificate context property length")
	}
	provInfo = (*C.CRYPT_KEY_PROV_INFO)(C.malloc(C.size_t(cbData)))
	defer C.free(unsafe.Pointer(provInfo))
	if C.CertGetCertificateContextProperty(c.pCert, C.CERT_KEY_PROV_INFO_PROP_ID, unsafe.Pointer(provInfo), &cbData) == 0 {
		return res, getErr("Error getting certificate context property")
	}
	if C.CryptAcquireContextW(&res.hProv, provInfo.pwszContainerName, provInfo.pwszProvName, provInfo.dwProvType, provInfo.dwFlags) == 0 {
		return res, getErr("Error acquiring context")
	}
	return res, nil
}
