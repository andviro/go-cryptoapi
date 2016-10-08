package csp

import (
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
