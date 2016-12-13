package csp

import (
	"gopkg.in/tylerb/is.v1"
	"testing"
)

func TestCertInfo(t *testing.T) {
	is := is.New(t)

	crt := getCert()
	info := crt.Info()
	is.NotZero(info)

	s, err := info.SubjectStr()
	is.NotErr(err)
	is.NotZero(s)

	s, err = info.IssuerStr()
	is.NotErr(err)
	is.NotZero(s)

	is.NotZero(info.SignatureAlgorithm())
	is.NotZero(info.PublicKeyAlgorithm())
	is.NotZero(len(info.PublicKeyBytes()))
}
