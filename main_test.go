package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersion(t *testing.T) {
	assert.Regexp(t, `^\d+\.\d+\.\d+$`, Version)
}
