package csp

import (
	"bytes"
	"encoding/base64"
	"gopkg.in/tylerb/is.v1"
	"testing"
)

var certData = `
MIIC/DCCAeagAwIBAgIRAOFquydyZU9tgXgQd5f2h6IwCwYJKoZIhvcNAQELMBIx
EDAOBgNVBAoTB0FjbWUgQ28wHhcNMTUwNzA1MDcyNzE2WhcNMTYwNzA0MDcyNzE2
WjASMRAwDgYDVQQKEwdBY21lIENvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAxGD/bLOlmcichuYV2sjPB8yIxW4ULhqhqyCKf0S0lUTdY0kUwuAOVO8w
3UWJX0QaFJpP8k0jY+wasyWvaqeiKvNtnNuvwjLrClvzwtnjtvgTYQPUbUM8JAsp
P/7FrOd41uL5jqTs0cfN/zxVQq5dePclYqfOQsbpNulHP7vXuyxMDl1yeeHK/S2T
3O8Fx7SErztjs2ThJbrvhZgrmdptOuAmR45oSyTnEpeiPysGlZOm4ntvFBXXjWi3
xeUClxHymlFbjA2Yk932PLuvcunAM5ihPZBknxUrZIriq6Vhu60L+L23jyxdP4/o
I2xlOzhUYi22YirYPTf0iNekTPA7bwIDAQABo1EwTzAOBgNVHQ8BAf8EBAMCAKAw
EwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAaBgNVHREEEzARgg9U
ZXN0R29DcnlwdG9BUEkwCwYJKoZIhvcNAQELA4IBAQB44i6Cjt1soIYcrXX/+BhM
/jEVxuYUY9VXEJ5RR+hxEhdPueB0i0b4NTKe417PA5jVHN9YeV6gKBXDMaAnN/E1
o5l+w7WxM03GGklH6TtH7aYsCIH8xUA5AkXB0ZNDLyDeMnq1sIzD/Z+ugIpMLuvt
VYFkQ2KwFCaqBJkq2Un9I3bUzXU4X9umubD4DUd1CSH1uRyQQfsnJjz8TWeS9nVe
Fy/OfGEaF8zewD+iSsmob52ifRG7qYcN1rEsyfHpQ33oooB/I8s9Nil9WatEpZNC
Sp4EAT/s6eUCx00m2uS2SJ83n7XHWr0hKxEtISL9tAA1fzwvT1eswO2IdKSBg47K
`

func getCert() *Cert {
	certRdr := base64.NewDecoder(base64.StdEncoding, bytes.NewReader(([]byte)(certData)))
	crt, err := NewCert(certRdr)
	if err != nil {
		panic(err)
	}
	return crt
}

func TestNewCert(t *testing.T) {
	is := is.New(t)

	crt := getCert()
	is.NotNil(crt.pCert)
	is.NotErr(crt.Close())
}

func TestCertProps(t *testing.T) {
	is := is.New(t)

	crt := getCert()
	thumb, _ := crt.ThumbPrint()
	is.Equal("4786a766633da61a2a2b1d668174172a9fc0af5e", thumb)
	subjectId, _ := crt.SubjectId()
	is.Equal("b091df915184fc44d9f9b23faf7b15939ecbca09", subjectId)
}

func TestMemoryStore(t *testing.T) {
	is := is.New(t)

	store, err := MemoryStore()
	is.NotErr(err)
	is.NotErr(store.Close())
}

func TestMyStore(t *testing.T) {
	is := is.New(t)

	store, err := SystemStore("MY")
	is.NotErr(err)
	is.NotErr(store.Close())
}

func TestFind(t *testing.T) {
	is := is.New(t)

	store, err := MemoryStore()
	is.NotErr(err)
	defer store.Close()

	crt := getCert()
	is.NotErr(store.Add(crt))

	crt2, err := store.GetByThumb("4786a766633da61a2a2b1d668174172a9fc0af5e")
	is.NotErr(err)
	is.Equal("4786a766633da61a2a2b1d668174172a9fc0af5e", crt2.MustThumbPrint())
	is.NotErr(crt2.Close())

	certsInStore := store.FindByThumb("4786a766633da61a2a2b1d668174172a9fc0af5e")
	is.Equal(1, len(certsInStore))
	for _, c := range certsInStore {
		is.NotErr(c.Close())
	}

	certsInStore2 := store.Certs()
	is.Equal(1, len(certsInStore2))
	for _, c := range certsInStore2 {
		is.NotErr(c.Close())
	}

	certsInStore3 := store.FindBySubject("")
	is.Equal(1, len(certsInStore3))
	for _, c := range certsInStore3 {
		is.NotErr(c.Close())
	}

	certsInStore4 := store.Certs()
	is.Equal(1, len(certsInStore4))
	for _, c := range certsInStore4 {
		is.NotErr(c.Close())
	}

	// BUG: FindBySubject followed by GetBySubject returns error
	//crt3, err := store.GetBySubject("")
	//is.NotErr(err)
	//is.Equal("4786a766633da61a2a2b1d668174172a9fc0af5e", crt3.MustThumbPrint())
	//is.NotErr(crt3.Close())
}
