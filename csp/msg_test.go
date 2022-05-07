package csp

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/go-multierror"
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
		certs := store.Certs()
		is.NotZero(len(certs))
		for _, c := range certs {
			is.NotZero(len(c.Bytes()))
			is.Lax().NotErr(msg.Verify(c))
		}
	})
	is.NotErr(msg.Close())
}

func TestMsgVerify_Detached(t *testing.T) {
	is := is.New(t)

	sig, err := ioutil.ReadFile("testdata/tinkoff.p7s")
	is.NotErr(err)
	data, err := os.Open("testdata/tinkoff.bin")
	is.NotErr(err)
	msg, err := OpenToVerify(sig)
	is.NotErr(err)
	_, err = io.Copy(msg, data)
	is.NotErr(err)

	store, err := msg.CertStore()
	is.NotErr(err)
	is.NotZero(store)

	certs := store.Certs()
	for i, c := range certs {
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
		_, err = io.Copy(msg, data)
		is.NotErr(err)
		is.NotErr(msg.Close())
		is.NotZero(dest.Bytes())
		ioutil.WriteFile("testdata/enc.bin", dest.Bytes(), 0666)
	})
	t.Run("decode", func(t *testing.T) {
		buf := new(bytes.Buffer)
		msg, err := OpenToDecode(buf)
		is.NotErr(err)
		_, err = dest.WriteTo(msg)
		is.NotErr(err)
		is.NotZero(buf.Bytes())
		is.Equal(buf.String(), "Test data")
		is.NotErr(msg.Close())
	})
}

func TestMsgEncode_Detached(t *testing.T) {
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

	//     data, err := ioutil.ReadFile("testdata/file.bin")
	//     is.NotErr(err)
	data := []byte(strings.Repeat("test data", 1))
	ioutil.WriteFile("testdata/dest.bin", data, 0666)
	dest := new(bytes.Buffer)
	t.Run("sign", func(t *testing.T) {
		msg, err := OpenToEncode(dest, EncodeOptions{
			Signers:  []Cert{crt},
			Detached: true,
		})
		is.NotErr(err)
		_, err = io.Copy(msg, bytes.NewReader(data))
		is.NotErr(err)
		is.NotErr(msg.Close())
		is.NotZero(dest.Bytes())
		ioutil.WriteFile("testdata/dest.sig", dest.Bytes(), 0666)
	})
	t.Run("verify", func(t *testing.T) {
		msg, err := OpenToVerify(dest.Bytes())
		is.NotErr(err)
		_, err = bytes.NewReader(data).WriteTo(msg)
		is.NotErr(err)
		store, err := msg.CertStore()
		is.NotErr(err)
		is.NotZero(store)
		certs := store.Certs()
		for _, c := range certs {
			is.NotZero(len(c.Bytes()))
			is.Lax().NotErr(msg.Verify(c))
		}
		is.NotErr(msg.Close())
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

func BenchmarkMsgEncode(b *testing.B) {
	if signCertThumb == "" {
		b.Skip("certificate for sign test not provided")
	}
	b.ReportAllocs()
	store, err := SystemStore("MY")
	if err != nil {
		panic(err)
	}
	defer store.Close()
	crt, err := store.GetByThumb(signCertThumb)
	if err != nil {
		panic(err)
	}
	defer crt.Close()
	data := bytes.NewBufferString("Test data")
	dest := new(bytes.Buffer)
	for i := 0; i < b.N; i++ {
		msg, err := OpenToEncode(dest, EncodeOptions{
			Signers: []Cert{crt},
		})
		if err != nil {
			panic(err)
		} else if _, err = data.WriteTo(msg); err != nil {
			panic(err)
		} else if err = msg.Close(); err != nil {
			panic(err)
		}
		dest.Reset()
	}
}

func TestSignVerify(t *testing.T) {
	if signCertThumb == "" {
		t.Skip("certificate for encrypt test not provided")
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
	dest := new(bytes.Buffer)
	data := strings.Repeat("test string", 1)
	src := strings.NewReader(data)
	err = func() (rErr error) {
		msg, err := OpenToEncode(dest, EncodeOptions{
			Signers:  []Cert{crt},
			Detached: true,
		})
		if err != nil {
			return fmt.Errorf("открытие сообщения на кодирование: %+v", err)
		}
		defer func() {
			if err := msg.Close(); err != nil {
				rErr = multierror.Append(rErr, fmt.Errorf("закрытие сообщения: %+v", err))
			}
		}()
		if _, err := io.Copy(msg, src); err != nil {
			return fmt.Errorf("кодирование сообщения: %+v", err)
		}
		return nil
	}()
	if err != nil {
		t.Fatal(err)
	}
	ioutil.WriteFile("testdata/detached.p7s", dest.Bytes(), 0666)
	ioutil.WriteFile("testdata/detached.txt", []byte(data), 0666)
	msg, err := OpenToVerify(dest.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strings.NewReader(data).WriteTo(msg); err != nil {
		t.Fatal(err)
	}
	msgStore, err := msg.CertStore()
	if err != nil {
		t.Fatal(err)
	}
	certs := msgStore.Certs()
	for _, c := range certs {
		t.Logf("%+v", c)
		if err := msg.Verify(c); err != nil {
			t.Errorf("%+v", err)
		}
	}
	if err := msg.Close(); err != nil {
		t.Fatal(err)
	}
}
