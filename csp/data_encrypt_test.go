package csp

import (
	"testing"

	"gopkg.in/tylerb/is.v1"
)

func TestEncryptData(t *testing.T) {
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

	var data []byte
	testData := "Test string"
	t.Run("encrypt data bytes", func(t *testing.T) {
		data, err = EncryptData([]byte(testData), EncryptOptions{
			Receivers: []Cert{crt},
		})
		is.NotErr(err)
		is.NotZero(data)
	})
	t.Run("decrypt data bytes", func(t *testing.T) {
		res, err := DecryptData(data, store)
		is.NotErr(err)
		is.Equal(string(res), testData)
	})
}

func BenchmarkEncryptData(b *testing.B) {
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
	testData := "Test string"
	for i := 0; i < b.N; i++ {
		data, err := EncryptData([]byte(testData), EncryptOptions{
			Receivers: []Cert{crt},
		})
		if err != nil {
			panic(err)
		}
		if len(data) == 0 {
			panic("zero data")
		}
	}
}

func BenchmarkDecryptData(b *testing.B) {
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
	testData := "Test string"
	data, err := EncryptData([]byte(testData), EncryptOptions{
		Receivers: []Cert{crt},
	})
	if err != nil {
		panic(err)
	}
	for i := 0; i < b.N; i++ {
		res, err := DecryptData(data, store)
		if err != nil {
			panic(err)
		}
		if string(res) != testData {
			panic("data is not decrypted correctly")
		}
	}
}

func TestBlockEncryptData(t *testing.T) {
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

	var data BlockEncryptedData
	testData := "Test string"
	t.Run("encrypt data bytes", func(t *testing.T) {
		data, err = BlockEncrypt(BlockEncryptOptions{Receiver: crt}, []byte(testData))
		is.NotErr(err)
		is.NotZero(data.CipherText)
		t.Logf("%#v", data)
	})
	t.Run("decrypt data bytes", func(t *testing.T) {
		res, err := BlockDecrypt(crt, data)
		is.NotErr(err)
		t.Logf("%q", string(res))
		is.Equal(string(res), testData)
	})
}
