package csp

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"gopkg.in/tylerb/is.v1"
)

func TestMsgDecode(t *testing.T) {
	is := is.New(t)

	f, err := os.Open("testdata/logical.cms")
	is.NotErr(err)
	defer f.Close()

	msg, err := OpenToDecode(f)
	is.NotErr(err)
	o, err := ioutil.TempFile("", "data")
	is.NotErr(err)
	defer o.Close()
	defer os.Remove(o.Name())

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

func TestMsgVerifyDetached(t *testing.T) {
	is := is.New(t)

	sig, err := ioutil.ReadFile("testdata/data1.p7s")
	is.NotErr(err)
	data, err := os.Open("testdata/data1.bin")
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

func TestMsgEncode(t *testing.T) {
	if signCertThumb == "" {
		t.Skip("certificate for sign test not provided")
	}
	is := is.New(t)

	store, err := SystemStore("MY")
	is.NotErr(err)
	defer store.Close()

	crt, err := store.GetByThumb("8e8e3128419de8a440768d70f78ddf9dfb0669c4")
	is.NotErr(err)
	defer crt.Close()

	data := bytes.NewBufferString("Test data")
	dest := new(bytes.Buffer)
	msg, err := OpenToEncode(dest, EncodeOptions{
		Signers: []Cert{crt},
	})
	is.NotErr(err)

	_, err = data.WriteTo(msg)
	is.NotErr(err)
	is.NotErr(msg.Close())
	is.NotZero(dest.Bytes())
}
