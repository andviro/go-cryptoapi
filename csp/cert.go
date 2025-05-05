package csp

/*
#include "common.h"

static CERT_CHAIN_PARA *mkCertChainPara() {
    CERT_CHAIN_PARA  *res = malloc(sizeof(CERT_CHAIN_PARA));
    memset(res, 0, sizeof(CERT_CHAIN_PARA));
    res->cbSize = sizeof(CERT_CHAIN_PARA);
    res->RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
    res->RequestedUsage.Usage.cUsageIdentifier=0;
    res->RequestedUsage.Usage.rgpszUsageIdentifier=NULL;
    //res->RequestedIssuancePolicy=NULL;
    //res->fCheckRevocationFreshnessTime=FALSE;
    //res->dwUrlRetrievalTimeout=0;
	return res;
}
*/
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

type CertChain struct {
	pCertChain C.PCCERT_CHAIN_CONTEXT
}

func (c CertChain) Close() {
	if c.pCertChain == nil {
		return
	}
	C.CertFreeCertificateChain(c.pCertChain)
}

type CertGetChainOptions struct {
	CacheEndCert          bool
	ThreadStoreSync       bool
	CacheOnlyURLRetrieval bool
	UseLocalMachineStore  bool
	EnableCacheAutoUpdate bool
	EnableShareStore      bool
	RevocationCheckMode   CertChainRevocationCheckMode
}

type CertChainRevocationCheckMode int

const (
	RevocationCheckEndCert CertChainRevocationCheckMode = iota
	RevocationCheckChain
	RevocationCheckChainExcludeRoot
	RevocationCheckCacheOnly
)

func (cgco CertGetChainOptions) ToFlags() C.DWORD {
	var res C.DWORD
	if cgco.CacheEndCert {
		res |= C.CERT_CHAIN_CACHE_END_CERT
	}
	if cgco.ThreadStoreSync {
		res |= C.CERT_CHAIN_THREAD_STORE_SYNC
	}
	if cgco.CacheOnlyURLRetrieval {
		res |= C.CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL
	}
	if cgco.UseLocalMachineStore {
		res |= C.CERT_CHAIN_USE_LOCAL_MACHINE_STORE
	}
	if cgco.EnableCacheAutoUpdate {
		res |= C.CERT_CHAIN_ENABLE_CACHE_AUTO_UPDATE
	}
	if cgco.EnableShareStore {
		res |= C.CERT_CHAIN_ENABLE_SHARE_STORE
	}
	switch cgco.RevocationCheckMode {
	case RevocationCheckEndCert:
		res |= C.CERT_CHAIN_REVOCATION_CHECK_END_CERT
	case RevocationCheckChain:
		res |= C.CERT_CHAIN_REVOCATION_CHECK_CHAIN
	case RevocationCheckChainExcludeRoot:
		res |= C.CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
	case RevocationCheckCacheOnly:
		res |= C.CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY
	}
	return res
}

// GetChain requests certificate trust chain from
func (c Cert) GetChain(opts CertGetChainOptions) (res CertChain, _ error) {
	pccp := C.mkCertChainPara()
	defer C.free(unsafe.Pointer(pccp))
	if C.CertGetCertificateChain(nil, c.pCert, nil, nil, pccp, opts.ToFlags(), nil, &res.pCertChain) == 0 {
		return res, getErr("Error getting certificate chain")
	}
	return res, nil
}
