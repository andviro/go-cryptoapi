package csp

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/andviro/goldie"
	"gopkg.in/tylerb/is.v1"
)

func TestMsgDecode(t *testing.T) {
	f, err := os.Open("testdata/logical.cms")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	msg, err := OpenToDecode(f)
	if err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, msg); err != nil {
		t.Fatal(err)
	}
	goldie.Assert(t, "msg-decode-logical", buf.Bytes())

	store, err := msg.CertStore()
	if err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	for i, c := range store.Certs() {
		if err := msg.Verify(c); err != nil {
			t.Error(err)
		}
		fmt.Fprintf(buf, "cert thumb %d: %s\n", i, c.MustThumbPrint())
	}
	goldie.Assert(t, "msg-decode-certs", buf.Bytes())
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

	data := bytes.NewBufferString(strings.Repeat("Test data", 10000))
	dest := new(bytes.Buffer)
	msg, err := OpenToEncode(dest, EncodeOptions{
		Signers: []Cert{crt},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = data.WriteTo(msg); err != nil {
		t.Fatal(err)
	}
	if err = msg.Close(); err != nil {
		t.Fatal(err)
	}
	goldie.Assert(t, "msg-encode", dest.Bytes())
}
