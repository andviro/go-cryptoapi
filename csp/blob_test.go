package csp

import (
	"bytes"
	_ "embed"
	"encoding/asn1"
	"testing"
)

//go:embed testdata/cipher1.bin
var testCipher1 []byte

//go:embed testdata/cipher2.bin
var testCipher2 []byte

func TestDecodeGostTransportASN(t *testing.T) {
	var dest Gost2001KeyTransportASN1
	if _, err := asn1.Unmarshal(testCipher2, &dest); err != nil {
		t.Fatal(err)
	}
	var pubKey []byte
	if _, err := asn1.Unmarshal(dest.TransportParameters.EphemeralPublicKey.EncapsulatedPublicKey.Bytes, &pubKey); err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v, %d", dest, len(pubKey))
	data, err := asn1.Marshal(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, testCipher2) {
		t.Error("marshaled and unmarshaled data do not match")
	}
}
