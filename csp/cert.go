package csp

//#include "common.h"
import "C"

import (
	"encoding/hex"
	"io"
	"io/ioutil"
	"unsafe"
)

type Cert struct {
	pCert *C.CERT_CONTEXT
}

// NewCert creates certificate context from io.Reader containing certificate
// in X509 encoding
func NewCert(r io.Reader) (*Cert, error) {
	var pCert C.PCCERT_CONTEXT
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	pCert = C.CertCreateCertificateContext(C.MY_ENC_TYPE, (*C.BYTE)(unsafe.Pointer(&buf[0])), C.DWORD(len(buf)))
	if pCert == C.PCCERT_CONTEXT(nil) {
		return nil, getErr("Error creating certficate context")
	}
	return &Cert{pCert}, nil
}

// Close releases certificate context
func (c *Cert) Close() error {
	if c == nil {
		return nil
	}
	if C.CertFreeCertificateContext(c.pCert) == 0 {
		return getErr("Error releasing certificate context")
	}
	return nil
}

type CertPropertyId C.DWORD

const (
	CertHashProp          CertPropertyId = C.CERT_HASH_PROP_ID
	CertKeyIdentifierProp CertPropertyId = C.CERT_KEY_IDENTIFIER_PROP_ID
	CertProvInfoProp      CertPropertyId = C.CERT_KEY_PROV_INFO_PROP_ID
)

// GetProperty is a base function for extracting certificate context properties
func (c *Cert) GetProperty(propId CertPropertyId) ([]byte, error) {
	var slen C.DWORD
	var res []byte
	if C.CertGetCertificateContextProperty(c.pCert, C.DWORD(propId), nil, &slen) == 0 {
		return res, getErr("Error getting cert context property size")
	}
	res = make([]byte, slen)
	if C.CertGetCertificateContextProperty(c.pCert, C.DWORD(propId), unsafe.Pointer(&res[0]), &slen) == 0 {
		return res, getErr("Error getting cert context property body")
	}
	return res, nil
}

// ThumbPrint returns certificate's hash as a hexadecimal string
func (c *Cert) ThumbPrint() (string, error) {
	thumb, err := c.GetProperty(CertHashProp)
	return hex.EncodeToString(thumb), err
}

// MustThumbprint returns certificate's hash as a hexadecimal string or panics
func (c *Cert) MustThumbPrint() string {
	if thumb, err := c.ThumbPrint(); err != nil {
		panic(err)
	} else {
		return thumb
	}
}

// SubjectId returs certificate's subject public key Id as a hexadecimal string
func (c *Cert) SubjectId() (string, error) {
	thumb, err := c.GetProperty(CertKeyIdentifierProp)
	return hex.EncodeToString(thumb), err
}

// MustSubjectId returns certificate's subject id or panics
func (c *Cert) MustSubjectId() string {
	if subj, err := c.SubjectId(); err != nil {
		panic(err)
	} else {
		return subj
	}
}
