package csp

import (
	//"fmt"
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

var (
	provName string
	provType ProvType
)

func TestContextVerify(t *testing.T) {
	x, err := AcquireCtx("", provName, provType, CryptVerifyContext)
	require.NoError(t, err)
	assert.NotNil(t, x.hProv)
	err = x.Close()
	assert.NoError(t, err)

}

func TestEnumProviders(t *testing.T) {
	x, err := EnumProviders()
	require.Nil(t, err, "Enumeration must pass")
	assert.NotEmpty(t, x, "There must be at least 1 provider")
}

func TestErrorContext(t *testing.T) {
	err := DeleteCtx(Container("NotExistentContext"), provName, provType)
	cerr, ok := err.(*CspError)
	assert.True(t, ok)
	assert.Equal(t, ErrKeysetNotDef, cerr.Code)
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
