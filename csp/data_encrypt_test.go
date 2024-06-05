package csp

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"
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
			Receivers:  []Cert{crt},
			EncryptOID: EncryptOIDMagma,
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
		data, err = BlockEncrypt(BlockEncryptOptions{
			Receiver: crt,
		}, []byte(testData))
		is.NotErr(err)
		is.NotZero(data.CipherText)
		t.Logf("%#v", data)
		t.Logf("%d", len(data.SessionPublicKey))
	})

	transport, err := data.ToGOST2001KeyTransportASN1()
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Logf("%#v", transport)
	t.Run("decrypt data bytes", func(t *testing.T) {
		dataStream := make([]byte, len(data.CipherText)+len(data.IV))
		copy(dataStream, data.IV)
		copy(dataStream[len(data.IV):], data.CipherText)
		blockEncryptedData, err := transport.ToBlockEncryptedData(dataStream)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%#v", blockEncryptedData)
		t.Logf("%d", len(blockEncryptedData.SessionPublicKey))
		data, err := BlockDecrypt(crt, blockEncryptedData)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, []byte(testData)) {
			t.Error("decrypted data does not match")
		}
	})
}

func autoDecode(src []byte) ([]byte, error) {
	if !bytes.HasPrefix(src, []byte("-----")) {
		return src, nil
	}
	block, _ := pem.Decode(src)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("неверный формат PEM")
	}
	return block.Bytes, nil
}

func TestBlockEncryptForCert(t *testing.T) {
	certData, err := ioutil.ReadFile("testdata/dest.crt")
	if err != nil {
		t.Skip(err.Error())
	}
	certBytes, err := autoDecode(certData)
	if err != nil {
		t.Fatal(err)
	}
	crt, err := ParseCert(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	var data BlockEncryptedData
	testData := "Test string"
	t.Run("encrypt data bytes", func(t *testing.T) {
		data, err = BlockEncrypt(BlockEncryptOptions{
			Receiver: crt,
		}, []byte(testData))
		if err != nil {
			t.Error(err.Error())
		}
		t.Logf("%#v", data)
	})
}

func TestBlockDecryptDataFile(t *testing.T) {
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

	data := BlockEncryptedData{}
	pkBlob, err := ioutil.ReadFile("testdata/session_PublicKey.bin")
	if err != nil {
		t.Fatal(err)
	}
	data.SessionPublicKey = pkBlob[len(pkBlob)-64:]
	if data.IV, err = ioutil.ReadFile("testdata/vector.bin"); err != nil {
		t.Fatal(err)
	}
	if data.CipherText, err = ioutil.ReadFile("testdata/encrypt.bin"); err != nil {
		t.Fatal(err)
	}
	if data.SessionKey.EncryptedKey, err = ioutil.ReadFile("testdata/session_EncryptedKey.bin"); err != nil {
		t.Fatal(err)
	}
	if data.SessionKey.SeanceVector, err = ioutil.ReadFile("testdata/session_SV.bin"); err != nil {
		t.Fatal(err)
	}
	if data.SessionKey.MACKey, err = ioutil.ReadFile("testdata/session_MacKey.bin"); err != nil {
		t.Fatal(err)
	}
	if data.SessionKey.EncryptionParamSet, err = ioutil.ReadFile("testdata/EncryptionParam.bin"); err != nil {
		t.Fatal(err)
	}
	_, err = BlockDecrypt(crt, data)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecryptData_NewAlg(t *testing.T) {
	store, err := SystemStore("MY")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, tc := range []string{
		"testdata/0e5d3163fecf404ea0c67d09c5e3ab9e.bin",
		"testdata/4028f91308c24f26914217b84cfdc6fe.bin",
		"testdata/c91f4f27c4764d3b821f475297ec16d1.bin",
		"testdata/1cd658e184a74f1c899144a4a69fdb21.bin",
	} {
		t.Run(filepath.Base(tc), func(t *testing.T) {
			data, err := ioutil.ReadFile(tc)
			if err != nil {
				t.Fatal(err)
			}
			res, err := DecryptData(data, store)
			if err != nil {
				t.Fatal(err)
			}
			ioutil.WriteFile(tc+".decr", res, 0664)
		})
	}
}
