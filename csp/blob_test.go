package csp

import (
	"bytes"
	"encoding/asn1"
	"os"
	"testing"
)

func TestDecodeGostTransportASN(t *testing.T) {
	var dest Gost2001KeyTransportASN1
	testData, err := os.ReadFile("testdata/cipher2.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := asn1.Unmarshal(testData, &dest); err != nil {
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
	if !bytes.Equal(data, testData) {
		t.Error("marshaled and unmarshaled data do not match")
	}
}
