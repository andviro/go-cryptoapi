package csp

import (
	"fmt"
	"testing"
)

func TestHash_Sum(t *testing.T) {
	h, err := NewHash(512)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(h, "%s", "test")
	t.Logf("%x", h.Sum(nil))
}
