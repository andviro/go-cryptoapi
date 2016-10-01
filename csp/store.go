package csp

/*
#include "common.h"
HCERTSTORE openStoreMem() {
	return CertOpenStore(CERT_STORE_PROV_MEMORY, MY_ENC_TYPE, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
}


HCERTSTORE openStoreSystem(HCRYPTPROV hProv, CHAR *proto) {
	return CertOpenStore(
		CERT_STORE_PROV_SYSTEM_A,          // The store provider type
		0,                               // The encoding type is
		// not needed
		hProv,                            // Use the default HCRYPTPROV
		// Set the store location in a
		// registry location
		CERT_STORE_NO_CRYPT_RELEASE_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
		proto                            // The store name as a Unicode
		// string
	);
}

*/
import "C"

import (
	"encoding/hex"
	//"io"
	//"io/ioutil"
	//"fmt"
	"unsafe"
)

// CertStore incapsulates certificate store
type CertStore struct {
	hStore C.HCERTSTORE
}

// MemoryStore returns handle to new empty in-memory certificate store
func MemoryStore() (*CertStore, error) {
	var res CertStore
	res.hStore = C.openStoreMem()
	if res.hStore == C.HCERTSTORE(nil) {
		return &res, getErr("Error creating memory cert store")
	}
	return &res, nil
}

// SystemStore returns handle to certificate store with certain name, using
// default system cryptoprovider
func SystemStore(name string) (*CertStore, error) {
	var res CertStore
	cName := unsafe.Pointer(C.CString(name))
	defer C.free(cName)

	res.hStore = C.openStoreSystem(C.HCRYPTPROV(0), (*C.CHAR)(cName))
	if res.hStore == C.HCERTSTORE(nil) {
		return &res, getErr("Error getting system cert store")
	}
	return &res, nil
}

// CertStore method returns handle to certificate store in certain CSP context
func (c *Ctx) CertStore(name string) (*CertStore, error) {
	var res CertStore
	cName := charPtr(name)
	defer freePtr(cName)

	res.hStore = C.openStoreSystem(c.hProv, cName)
	if res.hStore == C.HCERTSTORE(nil) {
		return &res, getErr("Error getting system cert store")
	}
	return &res, nil
}

// Close releases cert store handle
func (s *CertStore) Close() error {
	if C.CertCloseStore(s.hStore, C.CERT_CLOSE_STORE_CHECK_FLAG) == 0 {
		return getErr("Error closing cert store")
	}
	return nil
}

// FindCerts returns slice of *Cert's in store that satisfy findType and findPara
func (s *CertStore) FindCerts(findType C.DWORD, findPara unsafe.Pointer) []*Cert {
	var res []*Cert

	for pCert := C.CertFindCertificateInStore(s.hStore, C.MY_ENC_TYPE, 0, findType, findPara, nil); pCert != nil; pCert = C.CertFindCertificateInStore(s.hStore, C.MY_ENC_TYPE, 0, findType, findPara, pCert) {
		pCertDup := C.CertDuplicateCertificateContext(pCert)
		res = append(res, &Cert{pCertDup})
	}
	return res
}

// GetCert returns first of Cert's in store that satisfy findType and findPara
func (s *CertStore) GetCert(findType C.DWORD, findPara unsafe.Pointer) *Cert {
	if pCert := C.CertFindCertificateInStore(s.hStore, C.MY_ENC_TYPE, 0, findType, findPara, nil); pCert != nil {
		return &Cert{pCert}
	}
	return nil
}

// FindBySubject returns slice of certificates with a subject that matches
// string
func (s *CertStore) FindBySubject(subject string) []*Cert {
	cSubject := unsafe.Pointer(C.CString(subject))
	defer C.free(cSubject)
	return s.FindCerts(C.CERT_FIND_SUBJECT_STR, cSubject)
}

// FindByThumb returns slice of certificates that match given thumbprint. If
// thumbprint supplied could not be decoded from string, FindByThumb will
// return nil slice
func (s *CertStore) FindByThumb(thumb string) []*Cert {
	bThumb, err := hex.DecodeString(thumb)
	if err != nil {
		return nil
	}
	var hashBlob C.CRYPT_HASH_BLOB
	hashBlob.cbData = C.DWORD(len(bThumb))
	bThumbPtr := C.CBytes(bThumb)
	defer C.free(bThumbPtr)
	hashBlob.pbData = (*C.BYTE)(bThumbPtr)
	return s.FindCerts(C.CERT_FIND_HASH, unsafe.Pointer(&hashBlob))
}

// GetByThumb returns first certificate in store that match given thumbprint
func (s *CertStore) GetByThumb(thumb string) (*Cert, error) {
	bThumb, err := hex.DecodeString(thumb)
	if err != nil {
		return nil, err
	}
	var hashBlob C.CRYPT_HASH_BLOB
	hashBlob.cbData = C.DWORD(len(bThumb))
	bThumbPtr := C.CBytes(bThumb)
	defer C.free(bThumbPtr)
	hashBlob.pbData = (*C.BYTE)(bThumbPtr)
	if crt := s.GetCert(C.CERT_FIND_HASH, unsafe.Pointer(&hashBlob)); crt == nil {
		return nil, getErr("Error looking up certificate by thumb")
	} else {
		return crt, nil
	}
}

// GetBySubject returns first certificate with a subject that matches
// given string
func (s *CertStore) GetBySubject(subject string) (*Cert, error) {
	cSubject := unsafe.Pointer(C.CString(subject))
	defer C.free(cSubject)
	if crt := s.GetCert(C.CERT_FIND_SUBJECT_STR, cSubject); crt == nil {
		return nil, getErr("Error looking up certificate by subject string")
	} else {
		return crt, nil
	}
}

// Add inserts certificate into store replacing existing certificate link if
// it's already added
func (s *CertStore) Add(cert *Cert) error {
	if C.CertAddCertificateContextToStore(s.hStore, cert.pCert, C.CERT_STORE_ADD_REPLACE_EXISTING, nil) == 0 {
		return getErr("Couldn't add certificate to store")
	}
	return nil
}

func (s *CertStore) Certs() []*Cert {
	var res []*Cert

	for pCert := C.CertEnumCertificatesInStore(s.hStore, nil); pCert != nil; pCert = C.CertEnumCertificatesInStore(s.hStore, pCert) {
		pCertDup := C.CertDuplicateCertificateContext(pCert)
		res = append(res, &Cert{pCertDup})
	}
	return res
}
