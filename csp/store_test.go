package csp

import (
	"encoding/base64"
	"math/big"
	"testing"
)

func TestStore_GetByID(t *testing.T) {
	issuer := `MIIBOTEpMCcGA1UEAwwg0JDQniAi0JrQkNCb0KPQk9CQINCQ0KHQotCg0JDQmyIxKTAnBgNVBAoMINCQ0J4gItCa0JDQm9Cj0JPQkCDQkNCh0KLQoNCQ0JsiMQswCQYDVQQGEwJSVTEtMCsGA1UECAwkNDAg0JrQsNC70YPQttGB0LrQsNGPINC+0LHQu9Cw0YHRgtGMMRkwFwYDVQQHDBDQsy4g0JrQsNC70YPQs9CwMRswGQYJKoZIhvcNAQkBFgxjYUBhc3RyYWwucnUxNzA1BgNVBAkMLtC/0LXRgNC10YPQu9C+0Log0KLQtdGA0LXQvdC40L3RgdC60LjQuSwg0LQuIDYxGjAYBggqhQMDgQMBARIMMDA0MDI5MDE3OTgxMRgwFgYFKoUDZAESDTEwMjQwMDE0MzQwNDk=`
	issuerName, err := base64.StdEncoding.DecodeString(issuer)
	if err != nil {
		t.Fatal(err)
	}
	serialNumber := new(big.Int)
	serialNumber, ok := serialNumber.SetString(`2444306731539621231973744265765453825`, 10)
	if !ok {
		t.Fatal("failed converting Int")
	}
	store, err := SystemStore("MY")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := store.GetByID(([]byte)(issuerName), serialNumber)
	if err != nil {
		t.Fatal(err)
	}
	cert.Close()
}
