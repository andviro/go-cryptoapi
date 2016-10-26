package csp

import (
	"net"
	"testing"
)

func TestNewCredentials(t *testing.T) {
	creds, err := NewCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if creds == nil {
		t.Error("Creds are nil")
	}
}

func TestClient(t *testing.T) {
	conn, err := net.Dial("tcp", "www.cryptopro.ru:4444")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Client(conn)
	if err != nil {
		t.Fatal(err)
	}
}
