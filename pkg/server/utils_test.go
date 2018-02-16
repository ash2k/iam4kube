package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseIp(t *testing.T) {
	ip, err := parseIp("1.1.1.1:123")
	require.NoError(t, err)
	assert.EqualValues(t, "1.1.1.1", ip)
}

func TestFailingParseIp1(t *testing.T) {
	_, err := parseIp("1.1.1.1")
	assert.EqualError(t, err, `failed to parse the ip "1.1.1.1"`)
}

func TestFailingParseIp2(t *testing.T) {
	_, err := parseIp(":123")
	assert.EqualError(t, err, `failed to parse the ip ":123"`)
}

func TestFailingParseIp3(t *testing.T) {
	_, err := parseIp("1.2.3:123")
	assert.EqualError(t, err, `failed to parse the ip "1.2.3:123"`)
}
