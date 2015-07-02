package main

import (
	//"fmt"
	"github.com/andviro/go-cryptoapi/csp"
)

func init() {
}

func main() {
	provs, err := csp.EnumProviders()
	if err != nil {
		panic(err)
	}

	ctx, err := csp.NewCtx("\\\\.\\HDIMAGE\\TestGoCryptoAPIContainer", provs[0].Name, provs[0].Type, csp.CryptNewKeyset)
	if err != nil {
		panic(err)
	}
	defer ctx.Close()

	if err := ctx.SetPassword("", csp.AtKeyExchange); err != nil {
		panic(err)
	}
	if err := ctx.SetPassword("", csp.AtSignature); err != nil {
		panic(err)
	}

	eKey, err := ctx.GenKey(csp.AtKeyExchange, csp.KeyArchivable)
	if err != nil {
		panic(err)
	}
	defer eKey.Close()

	sKey, err := ctx.GenKey(csp.AtSignature, csp.KeyArchivable)
	if err != nil {
		panic(err)
	}
	defer sKey.Close()
}
