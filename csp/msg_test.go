package csp

import (
	//"fmt"
	"gopkg.in/tylerb/is.v1"
	"os"
	"testing"
)

func TestCmsDecoder(t *testing.T) {
	is := is.New(t)

	f, err := os.Open("/tmp/logical.cms")
	is.NotErr(err)
	defer f.Close()

	ctx, err := AcquireCtx("", provName, provType, CryptVerifyContext)
	is.NotErr(err)

	msg, err := NewCmsDecoder(ctx)
	is.NotErr(err)
	o, err := os.Create("/tmp/logical.bin")
	is.NotErr(err)
	defer o.Close()

	n, err := msg.Decode(o, f)
	is.NotErr(err)
	is.NotZero(n)

	store, err := msg.CertStore()
	is.NotErr(err)
	is.NotZero(store)

	for _, c := range store.Certs() {
		is.NotErr(msg.Verify(c))
	}
	is.NotErr(msg.Close())
}
