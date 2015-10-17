package csp

import (
	//"fmt"
	"gopkg.in/tylerb/is.v1"
	"testing"
)

func TestCertInfo(t *testing.T) {
	is := is.New(t)

	crt := getCert()
	info := crt.Info()
	is.NotZero(info)

	is.NotZero(info.SignatureAlgorithm())
	is.NotZero(info.PublicKeyAlgorithm())
	is.NotZero(len(info.PublicKeyBytes()))
}
