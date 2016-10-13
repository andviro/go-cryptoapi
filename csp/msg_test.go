package csp

import (
	//"fmt"
	"gopkg.in/tylerb/is.v1"
	"io"
	"io/ioutil"
	"os"
	"testing"
)

func TestCmsDecoder(t *testing.T) {
	is := is.New(t)

	f, err := os.Open("/tmp/logical2.cms")
	is.NotErr(err)
	defer f.Close()

	msg, err := OpenToDecode(f)
	is.NotErr(err)
	o, err := os.Create("/tmp/logical2.bin")
	is.NotErr(err)
	defer o.Close()

	n, err := io.Copy(o, msg)
	is.NotErr(err)
	is.NotZero(n)

	store, err := msg.CertStore()
	is.NotErr(err)
	is.NotZero(store)

	for _, c := range store.Certs() {
		is.Lax().NotErr(msg.Verify(c))
	}
	is.NotErr(msg.Close())
}

func TestCmsDetached(t *testing.T) {
	is := is.New(t)

	sig, err := ioutil.ReadFile("/tmp/data1.p7s")
	is.NotErr(err)
	data, err := os.Open("/tmp/data1.bin")
	is.NotErr(err)
	msg, err := OpenToDecode(data, sig)
	is.NotErr(err)

	store, err := msg.CertStore()
	is.NotErr(err)
	is.NotZero(store)

	for _, c := range store.Certs() {
		is.Lax().NotErr(msg.Verify(c))
	}
	is.NotErr(msg.Close())
}
