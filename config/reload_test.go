package config

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReloadConfigString(t *testing.T) {
	c := NewC(test.NewLogger())
	require.NoError(t, c.LoadString("a: 1"))
	fail := false
	ran := 0
	c.RegisterReloadCallback(func(c *C, r *Reload) {
		ran++
		if fail {
			r.Failed()
		}
	})

	assert.Equal(t, ReloadResult{}, c.ReloadConfigString("a: 2"))
	fail = true
	assert.Equal(t, ReloadResult{Failed: true}, c.ReloadConfigString("a: 3"))
	assert.Equal(t, 2, ran)

	// A config that fails to load runs no callbacks and returns the error
	res := c.ReloadConfigString("a: [")
	require.Error(t, res.Err)
	assert.False(t, res.Failed)
	assert.Equal(t, 2, ran)
	assert.Equal(t, 3, c.GetInt("a", 0))
}

// A restart key is decided against what nebula is running, not the last config: the one a reload brought that
// needs a restart stays reported, reverting it drops it again, and a config that does not load doesn't change
// the verdict
func TestReloadRestartRequiredIsDiffedAgainstTheRunningConfig(t *testing.T) {
	c := NewC(test.NewLogger())
	require.NoError(t, c.LoadString("a: 1\nb: 1"))
	c.RegisterReloadCallback(func(c *C, r *Reload) { r.RestartRequiredIfChanged("a", "b") })

	// Nothing that needs a restart changed
	assert.Equal(t, ReloadResult{}, c.ReloadConfigString("a: 1\nb: 1\nc: 1"))
	assert.Equal(t, ReloadResult{RestartRequired: true, RestartKeys: []string{"a"}}, c.ReloadConfigString("a: 2\nb: 1\nc: 1"))

	// The restart is still needed, still naming the key
	assert.Equal(t, ReloadResult{RestartRequired: true, RestartKeys: []string{"a"}}, c.ReloadConfigString("a: 2\nb: 1\nc: 1"))

	// Reverting the key needs nothing, a restart would apply it to no effect
	assert.Equal(t, ReloadResult{}, c.ReloadConfigString("a: 1\nb: 1\nc: 1"))

	// And bringing it back needs one again
	assert.Equal(t, ReloadResult{RestartRequired: true, RestartKeys: []string{"a"}}, c.ReloadConfigString("a: 2\nb: 1\nc: 1"))

	res := c.ReloadConfigString("a: [")
	require.Error(t, res.Err)
	assert.True(t, res.RestartRequired, "a config that did not load leaves the pending restart standing")
	assert.Equal(t, []string{"a"}, res.RestartKeys)
}

// A key reported by more than one callback is listed once
func TestReloadRestartKeysDeduped(t *testing.T) {
	c := NewC(test.NewLogger())
	require.NoError(t, c.LoadString("a: 1\nb: 1"))
	c.RegisterReloadCallback(func(c *C, r *Reload) { r.RestartRequiredIfChanged("a") })
	c.RegisterReloadCallback(func(c *C, r *Reload) { r.RestartRequiredIfChanged("a", "b") })
	assert.Equal(t, []string{"a", "b"}, c.ReloadConfigString("a: 2\nb: 2").RestartKeys)
}

// A callback can require a restart without a key changing, a file the config points at may have
func TestReloadRestartRequiredWithoutAChange(t *testing.T) {
	c := NewC(test.NewLogger())
	require.NoError(t, c.LoadString("a: 1"))
	c.RegisterReloadCallback(func(c *C, r *Reload) { r.RestartRequired() })

	assert.Equal(t, ReloadResult{RestartRequired: true}, c.ReloadConfigString("a: 1"))
}

func TestReloadResultSummary(t *testing.T) {
	cases := []struct {
		res   ReloadResult
		level slog.Level
		msg   string
	}{
		{ReloadResult{}, slog.LevelInfo, "Config reload complete"},
		{ReloadResult{RestartRequired: true}, slog.LevelWarn, "Config reload was completed but requires a restart to fully apply"},
		{ReloadResult{Failed: true}, slog.LevelError, "Config reload completed with errors, review the logs"},
		{ReloadResult{Failed: true, RestartRequired: true}, slog.LevelError, "Config reload completed with errors and requires a restart to fully apply, review the logs"},
		{ReloadResult{Err: errors.New("bad yaml")}, slog.LevelError, "Config reload failed, the new config did not load"},
		{ReloadResult{Err: errors.New("bad yaml"), RestartRequired: true}, slog.LevelError, "Config reload failed, the new config did not load and a restart is still required"},
	}
	for _, tc := range cases {
		level, msg := tc.res.Summary()
		assert.Equal(t, tc.level, level, tc.msg)
		assert.Equal(t, tc.msg, msg)
	}

	res := ReloadResult{RestartRequired: true, RestartKeys: []string{"a", "b"}}
	assert.Equal(t, "Config reload was completed but requires a restart to fully apply, keys [a b]", res.String())

	// String includes the error
	assert.Equal(t, "Config reload failed, the new config did not load: bad yaml", ReloadResult{Err: errors.New("bad yaml")}.String())
}

// The initial load passes a nil Reload
func TestReloadNilIsSafe(t *testing.T) {
	var r *Reload
	r.Failed()
	r.RestartRequired()
	r.RestartRequiredIfChanged("a")
}

// A reload that fails partway is not what nebula runs, so repeating it unchanged still reports every key it
// changed rather than saying nothing changed since the last load
func TestReloadFailedThenRepeatedStillReportsItsChanges(t *testing.T) {
	c := NewC(test.NewLogger())
	require.NoError(t, c.LoadString("a: 1"))
	var applied []string
	c.RegisterReloadCallback(func(c *C, r *Reload) {
		if c.HasChanged("a") {
			applied = append(applied, "a")
			r.Failed()
		}
	})

	assert.Equal(t, ReloadResult{Failed: true}, c.ReloadConfigString("a: 2"))
	assert.Equal(t, ReloadResult{Failed: true}, c.ReloadConfigString("a: 2"), "the same reload is retried in full")
	assert.Equal(t, []string{"a", "a"}, applied)
}

// A key that a reload omits reads as a change to nil, whatever the getters would default it to. Subsystems that
// need the default handled right compare the getter's value, not the raw key
func TestReloadOmittedKeyReadsAsNil(t *testing.T) {
	c := NewC(test.NewLogger())
	require.NoError(t, c.LoadString("listen:\n  port: 4242"))
	c.RegisterReloadCallback(func(c *C, r *Reload) {
		if c.HasChanged("listen.port") {
			r.Failed()
		}
	})

	assert.Equal(t, ReloadResult{Failed: true}, c.ReloadConfigString("other: 1"))
	assert.Equal(t, ReloadResult{Failed: true}, c.ReloadConfigString("other: 1"), "nil still differs from what is running")
}

// A restart that names no key, like a cert that changes our networks, is re-decided by every reload that runs its
// callbacks and kept by one whose config does not load
func TestReloadKeylessRestartSurvivesAConfigThatDoesNotLoad(t *testing.T) {
	c := NewC(test.NewLogger())
	require.NoError(t, c.LoadString("a: 1"))
	c.RegisterReloadCallback(func(c *C, r *Reload) { r.RestartRequired() })

	assert.Equal(t, ReloadResult{RestartRequired: true}, c.ReloadConfigString("a: 1"))

	res := c.ReloadConfigString("a: [")
	require.Error(t, res.Err)
	assert.True(t, res.RestartRequired, "the pending restart stands")
	assert.Empty(t, res.RestartKeys, "and still names no key")

	assert.Equal(t, ReloadResult{RestartRequired: true}, c.ReloadConfigString("a: 1"), "the next good reload re-decides")
}
