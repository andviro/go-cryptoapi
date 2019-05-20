package csp

import (
	//"fmt"
	"errors"
	"flag"
	"fmt"
	"os"
	"testing"

	"gopkg.in/tylerb/is.v1"
)

var (
	provName      string
	signCertThumb string
	authCertSubjectID string
	provType      ProvType
)

func TestContextVerify(t *testing.T) {
	is := is.New(t)

	x, err := AcquireCtx("", provName, provType, CryptVerifyContext)
	is.NotErr(err)
	is.NotNil(x.hProv)
	err = x.Close()
	is.NotErr(err)

}

func TestEnumProviders(t *testing.T) {
	is := is.New(t)

	x, err := EnumProviders()
	is.NotErr(err)
	is.NotZero(x)
}

func TestErrorContext(t *testing.T) {
	is := is.New(t)

	err := DeleteCtx(Container("NotExistentContext"), provName, provType)
	cerr, ok := err.(Error)
	is.True(ok)
	is.Equal(fmt.Sprintf("%x", ErrBadKeyset), fmt.Sprintf("%x", cerr.Code))
}

func TestCtxStore(t *testing.T) {
	is := is.New(t)

	ctx, err := AcquireCtx("", provName, provType, CryptVerifyContext)
	is.NotErr(err)
	store, err := ctx.CertStore("MY")
	is.NotErr(err)
	is.NotErr(store.Close())
}

func testMain(m *testing.M) int {
	x, err := EnumProviders()
	if err != nil {
		panic(err)
	}
	if len(x) < 1 {
		panic(errors.New("Must be at least 1 CSP available"))
	}
	provName = x[0].Name
	provType = x[0].Type
	flag.StringVar(&signCertThumb, "cert", "", "certificate thumbprint for signing")
	flag.StringVar(&authCertSubjectID, "auth_cert", "", "certificate SubjectID for TLS auth")
	flag.Parse()
	if err := InitTls(); err != nil {
		panic(err)
	}
	defer DeinitTls()
	return m.Run()
}

func TestMain(m *testing.M) {
	os.Exit(testMain(m))
}
