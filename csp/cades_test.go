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

func TestVerifyDetached_RevocationCheckRuns(t *testing.T) {
	data, err := os.ReadFile("testdata/good.xml")
	if err != nil {
		t.Fatalf("read good.xml: %v", err)
	}
	sig, err := os.ReadFile("testdata/good.xml.sig")
	if err != nil {
		t.Fatalf("read good.xml.sig: %v", err)
	}

	before := revocationCheckCount()
	res, err := VerifyDetached(data, sig)
	after := revocationCheckCount()

	if err != nil || res.Status != VerifySuccess {
		t.Fatalf("good fixture should verify: status=%v err=%v", res.Status, err)
	}
	if after-before != 1 {
		t.Fatalf("revocation safety net not invoked: counter delta = %d (expected 1)",
			after-before)
	}
}

func TestVerifyDetached(t *testing.T) {
	cases := []struct {
		name       string
		data       string
		sig        string
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
			data, err := os.ReadFile(tc.data)
			if err != nil {
				t.Fatalf("read %s: %v", tc.data, err)
			}
			sig, err := os.ReadFile(tc.sig)
			if err != nil {
				t.Fatalf("read %s: %v", tc.sig, err)
			}

			res, err := VerifyDetached(data, sig)
			if res == nil {
				t.Fatalf("res nil (err=%v)", err)
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
