package csp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestNewCert(t *testing.T) {
	certRdr := base64.NewDecoder(base64.StdEncoding, bytes.NewReader(([]byte)(certData)))
	crt, err := NewCert(certRdr)
	assert.NoError(t, err)
	assert.NotNil(t, crt.pcert)
	assert.NoError(t, crt.Close())
}

func TestCertProps(t *testing.T) {
	certRdr := base64.NewDecoder(base64.StdEncoding, bytes.NewReader(([]byte)(certData)))
	crt, err := NewCert(certRdr)
	require.NoError(t, err)
	fmt.Println(crt.SubjectId())
	fmt.Println(crt.ThumbPrint())
}
