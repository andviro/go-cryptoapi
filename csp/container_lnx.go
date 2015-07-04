// +build !windows

package csp

import (
	"fmt"
)

// Container returns HDIMAGE container name for CryptoPro linux CSP
func Container(cont string) string {
	return fmt.Sprintf("\\\\.\\HDIMAGE\\%s", cont)
}
