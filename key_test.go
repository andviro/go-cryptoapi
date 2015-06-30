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

	x, err := NewCtx("\\\\.\\HDIMAGE\\test", provs[0].Name, provs[0].Type, CryptNewKeyset)
	require.Nil(t, err, "Must create new container")
	defer x.Close()

	sKey, err := x.GenKey(AtKeyExchange, KeyArchivable)
	require.Nil(t, err, "Must create signature key pair")
	defer sKey.Close()

	k, err := x.Key(AtSignature)
	require.Nil(t, err, "Must get AtSignature public key")
	defer k.Close()

}
