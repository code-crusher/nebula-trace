package cert

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestQuoteName(t *testing.T) {
	assert.Equal(t, `"host"`, QuoteName("host"))
	assert.Equal(t, `"evil\x1b[31m\n"`, QuoteName("evil\x1b[31m\n"))
	assert.Equal(t, `"`+strings.Repeat("a", MaxNameLength)+`"`, QuoteName(strings.Repeat("a", MaxNameLength)))
	assert.Equal(t, `"`+strings.Repeat("a", MaxNameLength)+`"...`, QuoteName(strings.Repeat("a", MaxNameLength+1)))
}

func TestNotYetValid(t *testing.T) {
	now := time.Now().Round(time.Second)
	c := &certificateV2{details: detailsV2{
		notBefore: now.Add(time.Minute),
		notAfter:  now.Add(time.Hour),
	}}

	assert.True(t, NotYetValid(c, now))
	// Expired covers both ends, NotYetValid is how a caller tells the future end apart
	assert.True(t, c.Expired(now))
	assert.False(t, NotYetValid(c, now.Add(2*time.Minute)))
	assert.False(t, c.Expired(now.Add(2*time.Minute)))
	// Exactly at NotBefore the certificate is valid
	assert.False(t, NotYetValid(c, now.Add(time.Minute)))
}
