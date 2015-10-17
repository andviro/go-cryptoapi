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

	name, err := info.Subject()
	is.NotErr(err)
	is.NotZero(name)
	info.MustSubject()

	iss, err := info.Issuer()
	is.NotErr(err)
	is.NotZero(iss)
	info.MustIssuer()
}
