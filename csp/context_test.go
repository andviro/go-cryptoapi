package csp

import (
	//"fmt"
	"errors"
	"gopkg.in/tylerb/is.v1"
	"os"
	"testing"
)

var (
	provName string
	provType ProvType
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
	cerr, ok := err.(*CspError)
	is.True(ok)
	is.Equal(ErrKeysetNotDef, cerr.Code)
}

func TestCtxStore(t *testing.T) {
	is := is.New(t)

	ctx, err := AcquireCtx("", provName, provType, CryptVerifyContext)
	is.NotErr(err)
	store, err := ctx.CertStore("MY")
	is.NotErr(err)
	is.NotErr(store.Close())
}

func TestMain(m *testing.M) {
	x, err := EnumProviders()
	if err != nil {
		panic(err)
	}
	if len(x) < 1 {
		panic(errors.New("Must be at least 1 CSP available"))
	}
	provName = x[0].Name
	provType = x[0].Type
	os.Exit(m.Run())
}
