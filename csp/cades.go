//go:build linux && amd64

package csp

/*
#cgo linux,amd64 CFLAGS: -I/opt/cprocsp/include/pki -DCADES_PARA_HAS_EXTRA_FIELDS
#cgo linux,amd64 LDFLAGS: -lcades

#include <string.h>
#include "common.h"
#include "cades.h"

// Fallbacks for symbols that may or may not be declared by CryptoPro headers
// on every CSP release. Values come from MS wincrypt.h / winerror.h.
#ifndef CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
#define CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT 0x40000000
#endif
#ifndef CERT_TRUST_IS_REVOKED
#define CERT_TRUST_IS_REVOKED 0x00000004
#endif
#ifndef CRYPT_E_REVOKED
#define CRYPT_E_REVOKED 0x80092010L
#endif

// g_revocation_check_count is a monotonic counter incremented on every
// check_revocation call. Test-only — exposed to Go via get_revocation_check_count.
// Updated with __atomic_fetch_add to remain race-free under concurrent verify.
static volatile long g_revocation_check_count = 0;
static long get_revocation_check_count(void) {
    return __atomic_load_n(&g_revocation_check_count, __ATOMIC_RELAXED);
}

// check_revocation runs a best-effort revocation pass via CertGetCertificateChain
// with CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT. Returns TRUE iff the
// chain builder confirmed the signer (or an intermediate) is revoked
// (TrustStatus.dwErrorStatus & CERT_TRUST_IS_REVOKED).
//
// This is *fail-open*: a CertGetCertificateChain failure, a CRL fetch timeout,
// an offline CDP, or a CERT_TRUST_REVOCATION_STATUS_UNKNOWN flag all map to
// FALSE (not-revoked). The rationale is availability — better miss a
// revocation than reject every signature during a CRL service blip — but
// callers needing strict-fail semantics should wrap with their own check.
static BOOL check_revocation(PCCERT_CONTEXT pSignerCert) {
    CERT_CHAIN_PARA chainPara;
    PCCERT_CHAIN_CONTEXT chainContext = NULL;
    BOOL revoked = FALSE;

    __atomic_fetch_add(&g_revocation_check_count, 1, __ATOMIC_RELAXED);

    memset(&chainPara, 0, sizeof(chainPara));
    chainPara.cbSize = sizeof(chainPara);

    if (CertGetCertificateChain(
            NULL, pSignerCert, NULL, NULL,
            &chainPara,
            CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
            NULL,
            &chainContext)) {
        if (chainContext->TrustStatus.dwErrorStatus & CERT_TRUST_IS_REVOKED) {
            revoked = TRUE;
        }
    }
    if (chainContext != NULL) {
        CertFreeCertificateChain(chainContext);
    }
    return revoked;
}

// verify_detached wraps CadesVerifyDetachedMessage so that all parameter
// structures live in C-stack memory. This is required because cgo forbids
// passing Go-stored Go pointers (and CADES_VERIFY_MESSAGE_PARA holds two
// inner pointers — pVerifyMessagePara / pCadesVerifyPara — which would
// trip the "Go pointer to unpinned Go pointer" runtime check if allocated
// on the Go side).
//
// On a successful Cades verification, this helper additionally invokes
// check_revocation as a best-effort hybrid safety net (see fail-open
// semantics on check_revocation). If the chain builder reports
// CERT_TRUST_IS_REVOKED, we overwrite out_info->dwStatus to
// ADES_VERIFY_END_CERT_REVOCATION and propagate CRYPT_E_REVOKED via
// SetLastError + a FALSE return.
static BOOL verify_detached(
        const BYTE* sig, DWORD sig_len,
        const BYTE* data, DWORD data_len,
        DWORD cades_type,
        BOOL do_revocation_check,
        PCADES_VERIFICATION_INFO* out_info) {
    CRYPT_VERIFY_MESSAGE_PARA verifyPara;
    CADES_VERIFICATION_PARA cadesPara;
    CADES_VERIFY_MESSAGE_PARA msgPara;

    memset(&verifyPara, 0, sizeof(verifyPara));
    verifyPara.cbSize = sizeof(verifyPara);
    verifyPara.dwMsgAndCertEncodingType = MY_ENC_TYPE;

    memset(&cadesPara, 0, sizeof(cadesPara));
    cadesPara.dwSize = sizeof(cadesPara);
    cadesPara.dwCadesType = cades_type;

    memset(&msgPara, 0, sizeof(msgPara));
    msgPara.dwSize = sizeof(msgPara);
    msgPara.pVerifyMessagePara = &verifyPara;
    msgPara.pCadesVerifyPara = &cadesPara;

    const BYTE* data_arr[1] = { data };
    DWORD data_len_arr[1] = { data_len };

    BOOL ok = CadesVerifyDetachedMessage(
            &msgPara, 0,
            sig, sig_len,
            1,
            (const BYTE**)data_arr, data_len_arr,
            out_info);

    if (ok && do_revocation_check && *out_info != NULL && (*out_info)->dwStatus == ADES_VERIFY_SUCCESS) {
        PCCERT_CONTEXT pSignerCert = (*out_info)->pSignerCert;
        if (pSignerCert != NULL && check_revocation(pSignerCert)) {
            (*out_info)->dwStatus = ADES_VERIFY_END_CERT_REVOCATION;
            SetLastError(CRYPT_E_REVOKED);
            return FALSE;
        }
    }

    return ok;
}
*/
import "C"

import (
	"errors"
	"math"
	"time"
)

// VerifyStatus enumerates result codes returned by CryptoPro CAdES verification.
// Values correspond to ADES_VERIFY_* defines in <pki/ades-core.h>.
type VerifyStatus uint32

const (
	VerifySuccess              VerifyStatus = 0x00
	VerifyInvalidRefsAndValues VerifyStatus = 0x01
	VerifySignerNotFound       VerifyStatus = 0x02
	VerifyNoValidSigTimestamp  VerifyStatus = 0x03
	VerifyRefsAndValuesNoMatch VerifyStatus = 0x04
	VerifyNoChain              VerifyStatus = 0x05
	VerifyEndCertRevocation    VerifyStatus = 0x06
	VerifyChainCertRevocation  VerifyStatus = 0x07
	VerifyBadSignature         VerifyStatus = 0x08
	VerifyNoValidCadesCTime    VerifyStatus = 0x09
	VerifyBadPolicy            VerifyStatus = 0x0A
	VerifyUnsupportedAttribute VerifyStatus = 0x0B
	VerifyFailedPolicy         VerifyStatus = 0x0C
	VerifyEcontentTypeNoMatch  VerifyStatus = 0x0D
	VerifyNoValidArchiveTime   VerifyStatus = 0x0E
)

// CadesType selects the signature format expected by VerifyDetached.
// Values mirror the CADES_* / PKCS7_TYPE defines from <pki/cades.h>.
type CadesType uint32

const (
	CadesPKCS7      CadesType = 0xFFFF // plain CMS / PKCS#7 without CAdES attributes
	CadesBES        CadesType = 0x0001
	CadesT          CadesType = 0x0005
	CadesXLongType1 CadesType = 0x005D
	CadesA          CadesType = 0x00DD
)

// VerifyOption configures a VerifyDetached invocation.
type VerifyOption func(*verifyConfig)

type verifyConfig struct {
	cadesType       CadesType
	checkRevocation bool
}

// WithCadesType selects a CAdES signature format. Default is CadesPKCS7.
func WithCadesType(t CadesType) VerifyOption {
	return func(c *verifyConfig) { c.cadesType = t }
}

// WithoutRevocationCheck disables the hybrid revocation safety net — useful
// for offline environments or as a performance shortcut when the caller
// already knows the chain has been validated recently. Equivalent in spirit
// to cryptcp's '-norev' flag.
func WithoutRevocationCheck() VerifyOption {
	return func(c *verifyConfig) { c.checkRevocation = false }
}

// VerifyResult carries the outcome of CadesVerifyDetachedMessage.
// SignerCert and NotBefore/NotAfter help distinguish "untrusted root" from
// "expired cert" when Status is non-Success. The caller owns SignerCert and
// must Close() it.
type VerifyResult struct {
	Status     VerifyStatus
	SignerCert Cert
	NotBefore  time.Time
	NotAfter   time.Time
}

// VerifyDetached verifies a detached PKCS#7/CMS signature against the given
// data. The trust anchor is the system "mroot" store (populated externally by
// certmgr).
//
// Revocation is checked via a hybrid safety net: after a successful Cades
// verification the binding does an additional CertGetCertificateChain pass
// with CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT to guarantee CRL/OCSP
// is consulted. A confirmed revocation surfaces as Status=VerifyEndCertRevocation
// + error code CRYPT_E_REVOKED (0x80092010). An offline / unreachable CRL is
// treated as 'not revoked' (failsafe).
func VerifyDetached(data, sig []byte, opts ...VerifyOption) (*VerifyResult, error) {
	if len(data) == 0 || len(sig) == 0 {
		return nil, errors.New("VerifyDetached: empty data or signature")
	}
	// CadesVerifyDetachedMessage takes DWORD (uint32) lengths; reject inputs
	// that would silently truncate on 64-bit Go.
	if uint64(len(data)) > math.MaxUint32 || uint64(len(sig)) > math.MaxUint32 {
		return nil, errors.New("VerifyDetached: input exceeds 4 GiB")
	}

	cfg := verifyConfig{
		cadesType:       CadesPKCS7,
		checkRevocation: true,
	}
	for _, o := range opts {
		o(&cfg)
	}

	// Copy buffers into C memory; the C helper handles all parameter wiring.
	cData := C.CBytes(data)
	defer C.free(cData)
	cSig := C.CBytes(sig)
	defer C.free(cSig)

	revFlag := C.BOOL(1)
	if !cfg.checkRevocation {
		revFlag = C.BOOL(0)
	}

	var info C.PCADES_VERIFICATION_INFO
	ok := C.verify_detached(
		(*C.BYTE)(cSig), C.DWORD(len(sig)),
		(*C.BYTE)(cData), C.DWORD(len(data)),
		C.DWORD(cfg.cadesType),
		revFlag,
		&info,
	)

	res := &VerifyResult{}
	if info != nil {
		defer C.CadesFreeVerificationInfo(info)
		res.Status = VerifyStatus(info.dwStatus)
		if info.pSignerCert != nil {
			res.SignerCert = Cert{pCert: C.CertDuplicateCertificateContext(info.pSignerCert)}
			res.NotBefore = fileTimeToTime(info.pSignerCert.pCertInfo.NotBefore)
			res.NotAfter = fileTimeToTime(info.pSignerCert.pCertInfo.NotAfter)
		}
	}

	if ok == 0 {
		return res, getErr("CadesVerifyDetachedMessage failed")
	}
	return res, nil
}

// revocationCheckCount returns the cumulative number of times the hybrid
// revocation safety net has run since process start. Test-only.
func revocationCheckCount() int64 {
	return int64(C.get_revocation_check_count())
}

// fileTimeToTime converts a Win32 FILETIME (100-ns ticks since 1601-01-01 UTC)
// to a Go time.Time. Returns zero time for an all-zero FILETIME.
func fileTimeToTime(ft C.FILETIME) time.Time {
	const ticksPerSecond = int64(10_000_000)
	const epochDiffSeconds = int64(11644473600)
	ticks := (int64(ft.dwHighDateTime) << 32) | int64(ft.dwLowDateTime)
	if ticks == 0 {
		return time.Time{}
	}
	sec := ticks/ticksPerSecond - epochDiffSeconds
	nsec := (ticks % ticksPerSecond) * 100
	return time.Unix(sec, nsec).UTC()
}
