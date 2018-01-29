package csp

import (
	"encoding/base64"
	"testing"

	"gopkg.in/tylerb/is.v1"
)

var certData = `
MIIDHzCCAs6gAwIBAgITEgAlHKiioEaX0w6yFgAAACUcqDAIBgYqhQMCAgMwfzEjMCEGCSqGSIb3
DQEJARYUc3VwcG9ydEBjcnlwdG9wcm8ucnUxCzAJBgNVBAYTAlJVMQ8wDQYDVQQHEwZNb3Njb3cx
FzAVBgNVBAoTDkNSWVBUTy1QUk8gTExDMSEwHwYDVQQDExhDUllQVE8tUFJPIFRlc3QgQ2VudGVy
IDIwHhcNMTgwMTI0MTIzMTAzWhcNMTgwNDI0MTI0MTAzWjAkMSIwIAYDVQQDDBlDU1AgVGVzdCBj
ZXJ0aWZpY2F0ZV8yMDEyMGYwHwYIKoUDBwEBAQEwEwYHKoUDAgIkAAYIKoUDBwEBAgIDQwAEQKwp
vrPwC5k0WSKyTseCf7V6OjnzwN07aJqNj2A9phaQd0/BicLQkf21xXoCI+TmQ6mFZGmTLvnbRgK8
rs8sqlijggF3MIIBczALBgNVHQ8EBAMCBPAwHQYDVR0lBBYwFAYIKwYBBQUHAwQGCCsGAQUFBwMC
MB0GA1UdDgQWBBTxxr0WOmM09CsjW27W3mUTRvRwzTAfBgNVHSMEGDAWgBQVMXywjRreZtcVnElS
lxckuQF6gzBZBgNVHR8EUjBQME6gTKBKhkhodHRwOi8vdGVzdGNhLmNyeXB0b3Byby5ydS9DZXJ0
RW5yb2xsL0NSWVBUTy1QUk8lMjBUZXN0JTIwQ2VudGVyJTIwMi5jcmwwgakGCCsGAQUFBwEBBIGc
MIGZMGEGCCsGAQUFBzAChlVodHRwOi8vdGVzdGNhLmNyeXB0b3Byby5ydS9DZXJ0RW5yb2xsL3Rl
c3QtY2EtMjAxNF9DUllQVE8tUFJPJTIwVGVzdCUyMENlbnRlciUyMDIuY3J0MDQGCCsGAQUFBzAB
hihodHRwOi8vdGVzdGNhLmNyeXB0b3Byby5ydS9vY3NwL29jc3Auc3JmMAgGBiqFAwICAwNBAI09
oVDNKzK++W1TKQr+ni0Ft6YZmuMLV1KOQFLNENqfsSfvM4e5ptsqUNM6AXfzJD0uebjJCvE8Vxxd
DlA1v9M=
`

const (
	certThumb     = "8443b5d408789c867c9037b2370fe1a24643e36d"
	certSubjectID = "f1c6bd163a6334f42b235b6ed6de651346f470cd"
	certSubject   = "CSP Test certificate_2012"
)

func getCert() Cert {
	data, _ := base64.StdEncoding.DecodeString(certData)
	crt, err := ParseCert(data)
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
	thumb, err := crt.ThumbPrint()
	is.NotErr(err)
	is.Equal(certThumb, thumb)
	subjectID, err := crt.SubjectID()
	is.NotErr(err)
	is.Equal(certSubjectID, subjectID)
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

	crt2, err := store.GetByThumb(certThumb)
	is.NotErr(err)
	is.Equal(certThumb, crt2.MustThumbPrint())
	is.NotErr(crt2.Close())

	crt2, err = store.GetBySubjectId(certSubjectID)
	is.NotErr(err)
	is.Equal(certSubjectID, crt2.MustSubjectID())
	is.NotErr(crt2.Close())

	certsInStore := store.FindByThumb(certThumb)
	is.Equal(1, len(certsInStore))
	for _, c := range certsInStore {
		is.NotErr(c.Close())
	}

	certsInStore = store.FindBySubjectId(certSubjectID)
	is.Equal(1, len(certsInStore))
	for _, c := range certsInStore {
		is.NotErr(c.Close())
	}

	certsInStore2 := store.Certs()
	is.Equal(1, len(certsInStore2))
	for _, c := range certsInStore2 {
		is.NotErr(c.Close())
	}

	certsInStore3 := store.FindBySubject(certSubject)
	is.NotZero(certsInStore3)
	for _, c := range certsInStore3 {
		is.NotErr(c.Close())
	}

	certsInStore4 := store.Certs()
	is.Equal(1, len(certsInStore4))
	for _, c := range certsInStore4 {
		is.NotErr(c.Close())
	}

	crt3, err := store.GetBySubject(certSubject)
	is.NotErr(err)
	is.Equal(certThumb, crt3.MustThumbPrint())
	is.NotErr(crt3.Close())
}

func TestExtractCert(t *testing.T) {
	is := is.New(t)

	crt := getCert()
	data := crt.Bytes()
	is.NotZero(data)
}
