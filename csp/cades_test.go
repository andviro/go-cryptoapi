//go:build linux && amd64

package csp

import (
	"errors"
	"os"
	"testing"
	"time"
)

// CERT_E_EXPIRED HRESULT from <winerror.h>; emitted by libpkivalidator when
// a chain element's NotAfter is in the past.
const certEExpired ErrorCode = 0x800B0101

// loadFixture reads a testdata file and skips the test/benchmark if it is
// missing. See csp/testdata/README.md for how to provision fixtures locally.
func loadFixture(tb testing.TB, name string) []byte {
	tb.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		if os.IsNotExist(err) {
			tb.Skipf("fixture missing: %s (see csp/testdata/README.md)", name)
		}
		tb.Fatalf("read %s: %v", name, err)
	}
	return data
}

func TestVerifyDetached_RevocationCheckRuns(t *testing.T) {
	data := loadFixture(t, "testdata/good.xml")
	sig := loadFixture(t, "testdata/good.xml.sig")

	before := revocationCheckCount()
	res, err := VerifyDetached(data, sig)
	after := revocationCheckCount()

	if res != nil && !res.SignerCert.IsZero() {
		defer res.SignerCert.Close()
	}
	if err != nil || res.Status != VerifySuccess {
		t.Fatalf("good fixture should verify: status=%v err=%v", res.Status, err)
	}
	if after-before != 1 {
		t.Fatalf("revocation safety net not invoked: counter delta = %d (expected 1)",
			after-before)
	}
}

func TestVerifyDetached_WithoutRevocationCheck(t *testing.T) {
	data := loadFixture(t, "testdata/good.xml")
	sig := loadFixture(t, "testdata/good.xml.sig")

	before := revocationCheckCount()
	res, err := VerifyDetached(data, sig, WithoutRevocationCheck())
	after := revocationCheckCount()

	if res != nil && !res.SignerCert.IsZero() {
		defer res.SignerCert.Close()
	}
	if err != nil || res.Status != VerifySuccess {
		t.Fatalf("expected success: status=%v err=%v", res.Status, err)
	}
	if after != before {
		t.Errorf("revocation safety net ran with WithoutRevocationCheck: delta=%d",
			after-before)
	}
}

// TestVerifyDetached_StrictRevocation_HappyPath validates that
// WithStrictRevocation does not regress the happy path when CRLs are
// reachable. Confirming fail-closed behaviour on actually-unknown
// revocation status requires an offline fixture and is out of scope here.
func TestVerifyDetached_StrictRevocation_HappyPath(t *testing.T) {
	data := loadFixture(t, "testdata/good.xml")
	sig := loadFixture(t, "testdata/good.xml.sig")

	res, err := VerifyDetached(data, sig, WithStrictRevocation())
	if res != nil && !res.SignerCert.IsZero() {
		defer res.SignerCert.Close()
	}
	if err != nil || res.Status != VerifySuccess {
		t.Fatalf("expected success in strict mode (CRL reachable): err=%v status=%v",
			err, res.Status)
	}
}

func TestVerifyDetached(t *testing.T) {
	cases := []struct {
		name       string
		data       string
		sig        string
		opts       []VerifyOption
		wantStatus VerifyStatus
		wantErr    bool
		check      func(t *testing.T, res *VerifyResult, err error)
	}{
		{
			name:       "good",
			data:       "testdata/good.xml",
			sig:        "testdata/good.xml.sig",
			wantStatus: VerifySuccess,
			wantErr:    false,
			check: func(t *testing.T, res *VerifyResult, err error) {
				now := time.Now()
				if res.NotBefore.IsZero() || !res.NotBefore.Before(now) {
					t.Errorf("NotBefore should be in the past, got %v", res.NotBefore)
				}
				if res.NotAfter.IsZero() || !res.NotAfter.After(now) {
					t.Errorf("NotAfter should be in the future, got %v", res.NotAfter)
				}
				subj, sErr := res.SignerCert.Info().SubjectStr()
				if sErr != nil || subj == "" {
					t.Errorf("SubjectStr: %q err=%v", subj, sErr)
				}
				if res.SignerCert.Serial() == "" {
					t.Errorf("Serial empty")
				}
				t.Logf("signer subject=%q serial=%s notBefore=%v notAfter=%v",
					subj, res.SignerCert.Serial(), res.NotBefore, res.NotAfter)
			},
		},
		{
			name:       "expired",
			data:       "testdata/expired.xml",
			sig:        "testdata/expired.xml.sig",
			wantStatus: VerifyNoChain,
			wantErr:    true,
			check: func(t *testing.T, res *VerifyResult, err error) {
				if res.NotAfter.IsZero() || !res.NotAfter.Before(time.Now()) {
					t.Errorf("expected NotAfter < now, got %v", res.NotAfter)
				}
				var cspErr Error
				if !errors.As(err, &cspErr) {
					t.Fatalf("expected csp.Error, got %T: %v", err, err)
				}
				if cspErr.Code != certEExpired {
					t.Errorf("expected CERT_E_EXPIRED (%#x), got %#x (%s)",
						uint32(certEExpired), uint32(cspErr.Code), cspErr.Code)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := loadFixture(t, tc.data)
			sig := loadFixture(t, tc.sig)

			res, err := VerifyDetached(data, sig, tc.opts...)
			if res == nil {
				t.Fatalf("res nil (err=%v)", err)
			}
			if !res.SignerCert.IsZero() {
				defer res.SignerCert.Close()
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v, wantErr=%v (res=%+v)", err, tc.wantErr, res)
			}
			if res.Status != tc.wantStatus {
				t.Fatalf("Status=%v, want %v (res=%+v, err=%v)",
					res.Status, tc.wantStatus, res, err)
			}
			if tc.check != nil {
				tc.check(t, res, err)
			}
		})
	}
}
