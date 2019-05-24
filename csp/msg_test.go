package csp

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"strings"
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

	crt, err := store.GetByThumb(signCertThumb)
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
	ioutil.WriteFile("test.p7s", dest.Bytes(), os.ModePerm)
}

func TestMsgEncrypt_Decrypt(t *testing.T) {
	if signCertThumb == "" {
		t.Skip("certificate for encrypt test not provided")
	}
	is := is.New(t)

	store, err := SystemStore("MY")
	is.NotErr(err)
	defer store.Close()

	crt, err := store.GetByThumb(signCertThumb)
	is.NotErr(err)
	defer crt.Close()

	dest := new(bytes.Buffer)
	t.Run("encrypt", func(t *testing.T) {
		data := bytes.NewBufferString(strings.Repeat("Test data", 100000))
		msg, err := OpenToEncrypt(dest, EncryptOptions{
			Receivers: []Cert{crt},
		})
		is.NotErr(err)

		_, err = data.WriteTo(msg)
		is.NotErr(err)
		is.NotErr(msg.Close())
		is.NotZero(dest.Bytes())
		ioutil.WriteFile("test.bin", dest.Bytes(), os.ModePerm)
	})

	t.Run("decrypt", func(t *testing.T) {
		msg, err := OpenToDecrypt(dest, store, 10000)
		is.NotErr(err)
		byteData, err := ioutil.ReadAll(msg)
		is.NotErr(err)
		ioutil.WriteFile("test.txt", byteData, os.ModePerm)
	})
}
