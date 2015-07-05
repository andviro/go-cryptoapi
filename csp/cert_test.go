package csp

import (
	"bytes"
	"encoding/base64"
	//"fmt"
	"github.com/stretchr/testify/assert"
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
	crt := getCert()
	assert.NotNil(t, crt.pcert)
	assert.NoError(t, crt.Close())
}

func TestCertProps(t *testing.T) {
	crt := getCert()
	thumb, _ := crt.ThumbPrint()
	assert.Equal(t, "4786a766633da61a2a2b1d668174172a9fc0af5e", thumb)
	subjectId, _ := crt.SubjectId()
	assert.Equal(t, "b091df915184fc44d9f9b23faf7b15939ecbca09", subjectId)
}
