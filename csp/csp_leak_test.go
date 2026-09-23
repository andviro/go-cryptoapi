package csp_test

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/andviro/go-cryptoapi/v2/csp"
)

// TestMsg_CallbacksReleased ensures that msg.Close() deallocates properly
func TestMsg_CallbacksReleased(t *testing.T) {
	const n, size = 200, 1 << 20
	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)
	before := ms.HeapInuse
	for range n {
		buf := bytes.NewBuffer(make([]byte, 0, size))
		buf.Write(make([]byte, size))
		msg, err := csp.OpenToDecode(buf)
		if err != nil {
			t.Fatal(err)
		}
		_ = msg.Close()
	}
	runtime.GC()
	runtime.ReadMemStats(&ms)
	if grown := int64(ms.HeapInuse) - int64(before); grown > 50<<20 {
		t.Fatalf("heap grew by %d MB after %d closed messages: callbacks leak", grown>>20, n)
	}
}
