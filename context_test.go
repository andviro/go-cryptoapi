package cryptoapi

import (
	//"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestContextVerify(t *testing.T) {
	x, err := NewCtx("", "", ProvGost2001, CryptVerifyContext)
	require.Nil(t, err, "Verify context must be created")
	defer x.Close()
	assert.NotNil(t, x.hProv, "HPROV must not be NULL")
}

func TestEnumProviders(t *testing.T) {
	x, err := EnumProviders()
	require.Nil(t, err, "Enumeration must pass")
	assert.NotEmpty(t, x, "There must be at least 1 provider")
}
