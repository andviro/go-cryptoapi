package main

import (
	"fmt"

	"github.com/andviro/go-cryptoapi/csp"
)

func init() {
}

func main() {
	provs, err := csp.EnumProviders()
	if err != nil {
		panic(err)
	}
	var prov csp.CryptoProvider
	for _, prov = range provs {
		if prov.Type == csp.ProvGost2012 {
			break
		}
	}
	ctx, err := csp.AcquireCtx(csp.Container("TestGoCryptoAPIContainer"), prov.Name, prov.Type, csp.CryptNewKeyset)
	if cspErr, ok := err.(csp.CspError); ok {
		if cspErr.Code == csp.ErrExists {
			fmt.Println("Container already exists")
			return
		}
	} else if err != nil {
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
