package cryptoapi

/*
#cgo linux CFLAGS: -I/opt/cprocsp/include/cpcsp -I/opt/cprocsp/include/asn1data/
#cgo linux,amd64 LDFLAGS: -L/opt/cprocsp/lib/amd64/ -lcapi10 -lcapi20 -lasn1data -lssp
#cgo linux,386 LDFLAGS: -L/opt/cprocsp/lib/ia32/ -lcapi10 -lcapi20 -lasn1data -lssp
#cgo windows LDFLAGS: -lcrypt32 -lpthread
#include "common.h"
*/
import "C"

import (
	"errors"
	"fmt"
)

type Ctx struct {
	ctx C.HCRYPTPROV
}

func GetErr(msg string) error {
	return errors.New(fmt.Sprintf("%s: %x", msg, C.GetLastError()))
}

func NewCtx() (*Ctx, error) {
	var hprov C.HCRYPTPROV

	if C.CryptAcquireContext(&hprov, nil, nil, 75, C.CRYPT_VERIFYCONTEXT) == 0 {
		return nil, GetErr("Error acquiring context")
	}
	return &Ctx{ctx: hprov}, nil
}

func main() {
	x, err := NewCtx()
	if err != nil {
		panic(err)
	}
	fmt.Println(x)
}
