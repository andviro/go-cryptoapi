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
//"encoding/hex"
//"io"
//"io/ioutil"
//"unsafe"
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
	cName := charPtr(name)
	defer freePtr(cName)

	res.hStore = C.openStoreSystem(C.HCRYPTPROV(0), cName)
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
