//go:build linux && amd64

package csp

import (
	"testing"
)

// loadBenchFixture loads the good.xml + good.xml.sig pair once per benchmark.
// Skips the benchmark if either fixture is missing (see csp/testdata/README.md).
func loadBenchFixture(b *testing.B) (data, sig []byte) {
	b.Helper()
	return loadFixture(b, "testdata/good.xml"), loadFixture(b, "testdata/good.xml.sig")
}

// warmRevocationCache does one sequential verify so the first parallel
// iteration doesn't pay the CRL fetch cost (libpkivalidator caches CRLs
// in /var/opt/cprocsp/).
func warmRevocationCache(b *testing.B, data, sig []byte) {
	b.Helper()
	res, err := VerifyDetached(data, sig)
	if err != nil {
		b.Fatalf("warm-up verify failed: %v", err)
	}
	if !res.SignerCert.IsZero() {
		_ = res.SignerCert.Close()
	}
}

// BenchmarkVerifyDetached_WithRevocation measures throughput of the full
// verify path including the hybrid revocation safety net.
func BenchmarkVerifyDetached_WithRevocation(b *testing.B) {
	data, sig := loadBenchFixture(b)
	warmRevocationCache(b, data, sig)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			res, err := VerifyDetached(data, sig)
			if err != nil || res.Status != VerifySuccess {
				b.Errorf("verify failed: status=%v err=%v", res.Status, err)
				return
			}
			if !res.SignerCert.IsZero() {
				_ = res.SignerCert.Close()
			}
		}
	})
}

// BenchmarkVerifyDetached_WithoutRevocation measures the verify path with
// the hybrid revocation pass disabled — i.e. only what CadesVerifyDetachedMessage
// itself does.
func BenchmarkVerifyDetached_WithoutRevocation(b *testing.B) {
	data, sig := loadBenchFixture(b)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			res, err := VerifyDetached(data, sig, WithoutRevocationCheck())
			if err != nil || res.Status != VerifySuccess {
				b.Errorf("verify failed: status=%v err=%v", res.Status, err)
				return
			}
			if !res.SignerCert.IsZero() {
				_ = res.SignerCert.Close()
			}
		}
	})
}
