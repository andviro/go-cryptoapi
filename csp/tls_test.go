package csp

import (
	"net"
	"testing"
)

func TestClient(t *testing.T) {
	conn, err := net.Dial("tcp", "www.cryptopro.ru:4444")
	if err != nil {
		t.Fatal(err)
	}

	store, err := SystemStore("MY")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	crt, err := store.GetBySubjectId("ce9c137415ffa8679f51ff3996dc8762432bc6ba")
	if err != nil {
		t.Fatal(err)
	}
	tlsConn, err := Client(conn, Config{
		ServerName:   "www.cryptopro.ru",
		Certificates: []Cert{crt},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = tlsConn.Close()
	if err != nil {
		t.Fatal(err)
	}
}
