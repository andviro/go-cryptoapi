package csp

//#include "common.h"
import "C"

import (
	"io"
	"io/ioutil"
	"unsafe"
)

type Cert struct {
	pcert C.PCCERT_CONTEXT
}

// NewCert creates certificate context from io.Reader containing certificate
// in X509 encoding
func NewCert(r io.Reader) (*Cert, error) {
	var pcert C.PCCERT_CONTEXT
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	pcert = C.CertCreateCertificateContext(C.MY_ENC_TYPE, (*C.BYTE)(unsafe.Pointer(&buf[0])), C.DWORD(len(buf)))
	if pcert == C.PCCERT_CONTEXT(nil) {
		return nil, getErr("Error creating certficate context")
	}
	return &Cert{pcert}, nil
}

// Close releases certificate context
func (c *Cert) Close() error {
	if c == nil {
		return nil
	}
	if C.CertFreeCertificateContext(c.pcert) == 0 {
		return getErr("Error releasing certificate context")
	}
	return nil
}
