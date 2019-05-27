package csp

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"gopkg.in/tylerb/is.v1"
)

func TestMsgDecode_Verify(t *testing.T) {
	is := is.New(t)

	f, err := os.Open("testdata/logical.cms")
	is.NotErr(err)
	defer f.Close()

	buf := new(bytes.Buffer)
	msg, err := OpenToDecode(buf)
	is.NotErr(err)
	t.Run("decode", func(t *testing.T) {
		_, err := io.Copy(msg, f)
		is.NotErr(err)
		is.NotZero(buf.Len())
	})

	t.Run("verify", func(t *testing.T) {
		store, err := msg.CertStore()
		is.NotErr(err)
		is.NotZero(store)
		for _, c := range store.Certs() {
			is.Lax().NotErr(msg.Verify(c))
		}
	})
	is.NotErr(msg.Close())
}

func TestMsgVerify_Detached(t *testing.T) {
	is := is.New(t)

	sig, err := ioutil.ReadFile("testdata/data1.p7s")
	is.NotErr(err)
	data, err := os.Open("testdata/data1.bin")
	is.NotErr(err)
	msg, err := OpenToVerify(sig)
	is.NotErr(err)
	_, err = io.Copy(msg, data)
	is.NotErr(err)

	store, err := msg.CertStore()
	is.NotErr(err)
	is.NotZero(store)

	for i, c := range store.Certs() {
		t.Run(fmt.Sprintf("verify %d", i), func(t *testing.T) {
			is.Lax().NotErr(msg.Verify(c))
		})
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
	t.Run("encode", func(t *testing.T) {
		msg, err := OpenToEncode(dest, EncodeOptions{
			Signers: []Cert{crt},
		})
		is.NotErr(err)
		_, err = data.WriteTo(msg)
		is.NotErr(err)
		is.NotErr(msg.Close())
		is.NotZero(dest.Bytes())
	})
	t.Run("decode", func(t *testing.T) {
		buf := new(bytes.Buffer)
		msg, err := OpenToDecode(buf)
		is.NotErr(err)
		_, err = dest.WriteTo(msg)
		is.NotErr(err)
		is.NotErr(msg.Close())
		is.NotZero(buf.Bytes())
		is.Equal(buf.String(), "Test data")
	})
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
	testData := strings.Repeat("Test data", 100000)
	t.Run("encrypt", func(t *testing.T) {
		data := bytes.NewBufferString(testData)
		msg, err := OpenToEncrypt(dest, EncryptOptions{
			Receivers: []Cert{crt},
		})
		is.NotErr(err)

		_, err = io.Copy(msg, data)
		is.NotErr(err)
		is.NotErr(msg.Close())
		is.NotZero(dest.Bytes())
	})

	t.Run("decrypt", func(t *testing.T) {
		newDest := new(bytes.Buffer)
		msg, err := OpenToDecrypt(newDest, store, 10000)
		is.NotErr(err)
		_, err = io.Copy(msg, dest)
		is.NotErr(err)
		is.Equal(newDest.String(), testData)
	})
}
