package cryptoapi

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestContextVerify(t *testing.T) {
	x, err := NewCtx()
	assert.Nil(t, err, "Verify context must be created")
	assert.NotNil(t, x.ctx, "HPROV must not be NULL")
}
