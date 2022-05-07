package csp

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"fmt"
	"testing"

	"github.com/andviro/goldie"
)

func TestHash_Sum(t *testing.T) {
	buf := new(bytes.Buffer)
	for _, algo := range []asn1.ObjectIdentifier{GOST_R3411, GOST_R3411_12_256, GOST_R3411_12_512} {
		for _, testStr := range []string{"", "some test string"} {
			func() {
				h, err := NewHash(HashOptions{HashAlg: algo})
				if err != nil {
					t.Error(err)
					return
				}
				defer func() {
					if err := h.Close(); err != nil {
						t.Error(err)
					}
				}()
				fmt.Fprintf(h, "%s", testStr)
				fmt.Fprintf(buf, "%s %d %q %x\n", algo, h.Size()*8, testStr, h.Sum(nil))
			}()
		}
	}
	goldie.Assert(t, "hash-sum", buf.Bytes())
}

func TestHash_HMAC_Sum(t *testing.T) {
	buf := new(bytes.Buffer)
	for _, algo := range []asn1.ObjectIdentifier{GOST_R3411, GOST_R3411_12_256, GOST_R3411_12_512} {
		for _, testKey := range []string{"", "1234", "some other key"} {
			for _, testStr := range []string{"", "The quick brown fox jumps over the lazy dog"} {
				func() {
					h, err := NewHMAC(algo, ([]byte)(testKey))
					if err != nil {
						t.Error(err)
						return
					}
					defer func() {
						if err := h.Close(); err != nil {
							t.Error(err)
						}
					}()
					fmt.Fprintf(buf, "%s %q %q %x\n", algo, testKey, testStr, h.Sum(([]byte)(testStr)))
				}()
			}
		}
	}
	goldie.Assert(t, "hash-hmac-sum", buf.Bytes())
}

func TestSignHash(t *testing.T) {
	if signCertThumb == "" {
		t.Skip("certificate for sign test not provided")
	}
	store, err := SystemStore("MY")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	crt, err := store.GetByThumb(signCertThumb)
	if err != nil {
		t.Fatal(err)
	}
	defer crt.Close()
	testData := "Test string"
	hash, err := NewHash(HashOptions{SignCert: crt})
	if err != nil {
		t.Fatal(err)
	}
	defer func(hash *Hash) {
		if err := hash.Close(); err != nil {
			t.Fatal(err)
		}
	}(hash)
	fmt.Fprintf(hash, "%s", testData)
	sig, err := hash.Sign()
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}
	t.Logf("signature: %x", sig)
	hash, err = NewHash(HashOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func(hash *Hash) {
		if err := hash.Close(); err != nil {
			t.Fatal(err)
		}
	}(hash)
	fmt.Fprintf(hash, "%s", testData)
	if err := hash.Verify(crt, sig); err != nil {
		t.Errorf("%+v", err)
	}
	hash.Reset()
	fmt.Fprintf(hash, "%s", "wrong data")
	var cryptErr Error
	if err := hash.Verify(crt, sig); !errors.As(err, &cryptErr) {
		t.Errorf("expected crypto Error, got %+v", err)
	} else if cryptErr.Code != 0x80090006 {
		t.Errorf("expected error 0x80090006, got %x", cryptErr.Code)
	}
}
