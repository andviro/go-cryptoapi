package csp

import (
	"gopkg.in/tylerb/is.v1"
	"testing"
)

func TestKey(t *testing.T) {
	is := is.New(t)

	provs, err := EnumProviders()
	is.NotZero(provs)

	ctx, err := AcquireCtx("TestGoCryptoAPIContainer", provs[0].Name, provs[0].Type, 0)
	is.NotErr(err)
	defer ctx.Close()

	k1, err := ctx.Key(AtSignature)
	is.Nil(err)
	defer k1.Close()

	k2, err := ctx.Key(AtSignature)
	is.Nil(err)
	defer k2.Close()
}
