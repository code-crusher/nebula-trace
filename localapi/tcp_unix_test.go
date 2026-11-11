//go:build !windows

package localapi

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/slackhq/nebula/commands"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInfoMovesBetweenSocketAndTCP: a reload can take the info API from a socket to an
// address and back, which is the point of supporting both from one endpoint. The target
// that is no longer served is gone: the socket node is removed, the address is closed.
func TestInfoMovesBetweenSocketAndTCP(t *testing.T) {
	ctx := context.Background()
	s := NewInfoServer(test.NewLogger(), stubInfoHandler())
	t.Cleanup(s.Stop)

	path := testSocket(t)
	require.NoError(t, s.Rebind(ctx, path, OwnerOnly()))
	assert.Equal(t, path, s.Path())
	assert.Empty(t, s.Addr())

	require.NoError(t, s.RebindTCP(ctx, "127.0.0.1:0"))
	addr := s.Addr()
	require.NotEmpty(t, addr)
	assert.Empty(t, s.Path(), "the socket was given up for the address")
	assert.NoFileExists(t, path)

	status, body := httpGetTCP(t, addr, "/v1/whoami?name=bob")
	assert.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{"name":"bob"}`, body)

	// And back to a socket, which the address gives way to.
	path2 := testSocket(t)
	require.NoError(t, s.Rebind(ctx, path2, OwnerOnly()))
	assert.Equal(t, path2, s.Path())
	assert.Empty(t, s.Addr())
	_, err := httpGetErr(t, addr, "/v1/whoami")
	assert.Error(t, err)

	status, _ = test.HTTPGet(t, path2, "/v1/whoami")
	assert.Equal(t, http.StatusOK, status)
}

// TestWireInfoTCP: the info API follows local_api.info.listen across reloads, moving
// between a socket and an address, and back off when disabled.
func TestWireInfoTCP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	ctlPath := testSocket(t)
	socketPath := testSocket(t)
	section := func(info string) string {
		return fmt.Sprintf("local_api:\n  control:\n    socket: %s\n  info:\n    enabled: true\n%s", ctlPath, info)
	}

	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(section("    listen: 127.0.0.1:0\n")))

	eps := Wire(ctx, test.NewLogger(), c, commands.New(), stubInfoHandler())
	t.Cleanup(eps.Stop)
	info := eps.Info
	addr := info.Addr()
	require.NotEmpty(t, addr, "served over TCP")
	assert.Empty(t, info.Path())

	status, _ := httpGetTCP(t, addr, "/v1/whoami")
	assert.Equal(t, http.StatusOK, status)

	// A reload to a socket moves it there, and the address stops answering.
	require.NoError(t, c.ReloadConfigString(section("    socket: "+socketPath+"\n")).Err)
	assert.Equal(t, socketPath, info.Path())
	assert.Empty(t, info.Addr())
	_, err := httpGetErr(t, addr, "/v1/whoami")
	assert.Error(t, err)

	// A reload back to an address moves it again.
	require.NoError(t, c.ReloadConfigString(section("    listen: 127.0.0.1:0\n")).Err)
	assert.NotEmpty(t, info.Addr())
	assert.Empty(t, info.Path())

	// Disabling takes it down whichever form it is in.
	require.NoError(t, c.ReloadConfigString(fmt.Sprintf("local_api:\n  control:\n    socket: %s\n  info:\n    enabled: false\n", ctlPath)).Err)
	assert.Empty(t, info.Addr())
	assert.Empty(t, info.Path())
}

// TestWireInfoTCPUnchangedConfigIsNotAMove: a reload of the same ":0" config is not a
// move, though the port the kernel chose is not the ":0" the config asked for. The
// comparison is of configured targets, so the endpoint is left where it is and no move
// is logged.
func TestWireInfoTCPUnchangedConfigIsNotAMove(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	cfg := "local_api:\n  info:\n    enabled: true\n    listen: 127.0.0.1:0\n"
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(cfg))

	var logs lockedBuffer
	srv := wireInfo(ctx, test.NewLoggerWithOutput(&logs), c, stubInfoHandler())
	t.Cleanup(srv.Stop)
	addr := srv.Addr()
	require.NotEmpty(t, addr)

	require.NoError(t, c.ReloadConfigString(cfg).Err)
	assert.Equal(t, addr, srv.Addr(), "the same config leaves the endpoint where it is")
	assert.NotContains(t, logs.String(), "Moved the local info API")
}

// TestWireInfoTCPKeepsRunningOnABadReload: a typo in a running TCP section keeps the
// address serving, and the log says the endpoint it kept, which for an address is its
// address rather than a socket path that is empty.
func TestWireInfoTCPKeepsRunningOnABadReload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	good := "local_api:\n  info:\n    enabled: true\n    listen: 127.0.0.1:0\n"
	c := config.NewC(test.NewLogger())
	require.NoError(t, c.LoadString(good))

	var logs lockedBuffer
	srv := wireInfo(ctx, test.NewLoggerWithOutput(&logs), c, stubInfoHandler())
	t.Cleanup(srv.Stop)
	addr := srv.Addr()
	require.NotEmpty(t, addr)

	// Both keys at once is a config error; the address keeps serving.
	require.NoError(t, c.ReloadConfigString(good+"    socket: /run/nebula/info.sock\n").Err)
	assert.Equal(t, addr, srv.Addr())
	assert.Contains(t, logs.String(), "keeping the current endpoint")
	assert.NotContains(t, logs.String(), "is not available")
	status, _ := httpGetTCP(t, addr, "/v1/whoami")
	assert.Equal(t, http.StatusOK, status)
}
