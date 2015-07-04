// +build windows

package csp

import (
	"fmt"
)

// Container simply returns container name for Windows
func Container(cont string) string {
	return cont
}
