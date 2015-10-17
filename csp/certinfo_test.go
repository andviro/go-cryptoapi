package csp

import (
	"fmt"
	"gopkg.in/tylerb/is.v1"
	"testing"
)

func TestCertInfo(t *testing.T) {
	is := is.New(t)

	crt := getCert()
	info := crt.Info()
	is.NotZero(info)

	fmt.Println(info.SignatureAlgorithm())
	fmt.Println(info.PublicKeyAlgorithm())
	fmt.Println(len(info.PublicKeyBytes()))
}
