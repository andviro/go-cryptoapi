package csp

import (
	"bytes"
	"io"
	"strings"
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
	testData := strings.Repeat("Test data", 10)
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
	t.Run("decrypt stream", func(t *testing.T) {
		newDest := new(bytes.Buffer)
		msg, err := OpenToDecrypt(newDest, store, 10000)
		is.NotErr(err)
		_, err = io.Copy(msg, bytes.NewReader(data))
		is.NotErr(err)
		is.Equal(newDest.String(), testData)
	})
}
