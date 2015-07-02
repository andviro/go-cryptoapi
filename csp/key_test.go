package csp

import (
	//"fmt"
	//"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestKey(t *testing.T) {
	provs, err := EnumProviders()
	require.NotEmpty(t, provs, "There must be at least 1 provider")

	ctx, err := NewCtx("TestGoCryptoAPIContainer", provs[0].Name, provs[0].Type, 0)
	require.NoError(t, err, "Create key container using 'createKeys' utility")
	defer ctx.Close()

	k1, err := ctx.Key(AtSignature)
	require.Nil(t, err, "Must get AtSignature public key")
	defer k1.Close()

	k2, err := ctx.Key(AtSignature)
	require.Nil(t, err, "Must get AtSignature public key")
	defer k2.Close()

}
