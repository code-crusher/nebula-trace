package localapi

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// httpDoTCP sends one request to the TCP address and returns the status, body and
// headers. It is test.HTTPDo for an address rather than a socket.
func httpDoTCP(t *testing.T, addr, method, target string) (int, string, http.Header) {
	t.Helper()

	req, err := http.NewRequest(method, "http://"+addr+target, nil)
	require.NoError(t, err)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, string(body), res.Header
}

// httpGetTCP is httpDoTCP for a GET whose headers the test does not read.
func httpGetTCP(t *testing.T, addr, target string) (int, string) {
	t.Helper()
	status, body, _ := httpDoTCP(t, addr, http.MethodGet, target)
	return status, body
}

// httpGetErr sends a GET and returns the transport error, if any, rather than requiring
// success: a test uses it to show an address that no longer answers.
func httpGetErr(t *testing.T, addr, target string) (int, error) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, "http://"+addr+target, nil)
	require.NoError(t, err)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)
	return res.StatusCode, nil
}

// TestParseListenAddr: a host:port is one address and a port, normalised; a wildcard, a
// name that would be resolved at bind time, and a malformed or portless address are each
// refused with the key named, because a wildcard is served on every interface the host
// has, where the Nebula firewall does not apply.
func TestParseListenAddr(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"10.42.0.1:8080", "10.42.0.1:8080"},
		{"127.0.0.1:80", "127.0.0.1:80"},
		{"[::1]:8080", "[::1]:8080"},
		{"[fd00::1]:8080", "[fd00::1]:8080"},
		{"127.0.0.1:0", "127.0.0.1:0"},
		{"10.42.0.1:08080", "10.42.0.1:8080"},
	} {
		got, err := parseListenAddr(tc.in)
		require.NoError(t, err, tc.in)
		assert.Equal(t, tc.want, got, tc.in)
	}

	for _, in := range []string{
		"0.0.0.0:8080",
		"[::]:8080",
		":8080",
		"localhost:8080",
		"10.42.0.1",
		"10.42.0.1:",
		"10.42.0.1:http",
		"10.42.0.1:99999",
		"not an address",
	} {
		_, err := parseListenAddr(in)
		require.Error(t, err, in)
		assert.ErrorContains(t, err, InfoListenKey, in)
	}

	// The wildcard is named as such, so the operator is told what to write instead.
	_, err := parseListenAddr("0.0.0.0:8080")
	assert.ErrorContains(t, err, "wildcard")
	assert.ErrorContains(t, err, "every interface")
	_, err = parseListenAddr(":8080")
	assert.ErrorContains(t, err, "wildcard")
	_, err = parseListenAddr("localhost:8080")
	assert.ErrorContains(t, err, "IP address")
}

// TestInfoConfigTCP: an enabled section served over TCP takes a listen address in place
// of a socket, refuses both keys at once, refuses neither, and refuses the socket's mode
// and group, which mean nothing to an address.
func TestInfoConfigTCP(t *testing.T) {
	load := func(t *testing.T, yaml string) (infoConfig, error) {
		t.Helper()
		c := config.NewC(test.NewLogger())
		require.NoError(t, c.LoadString(yaml))
		return infoConfigFrom(c)
	}
	section := func(extra string) string {
		return "local_api:\n  info:\n    enabled: true\n" + extra
	}

	cfg, err := load(t, section("    listen: 10.42.0.1:8080\n"))
	require.NoError(t, err)
	assert.True(t, cfg.tcp())
	assert.Equal(t, "10.42.0.1:8080", cfg.Listen)
	assert.Empty(t, cfg.Path)
	assert.Equal(t, Access{}, cfg.Access, "an address has no mode or group")

	_, err = load(t, section("    listen: 10.42.0.1:8080\n    socket: /run/nebula/info.sock\n"))
	require.ErrorContains(t, err, InfoSocketKey)
	require.ErrorContains(t, err, InfoListenKey)

	_, err = load(t, section(""))
	require.ErrorContains(t, err, InfoSocketKey)
	require.ErrorContains(t, err, InfoListenKey)

	for _, key := range []string{"socket_mode: \"0660\"", "group: node"} {
		_, err = load(t, section("    listen: 10.42.0.1:8080\n    "+key+"\n"))
		require.ErrorContains(t, err, strings.SplitN(key, ":", 2)[0], key)
		require.ErrorContains(t, err, InfoListenKey, key)
	}

	// The socket form still reads as before.
	cfg, err = load(t, section("    socket: /run/nebula/info.sock\n"))
	require.NoError(t, err)
	assert.False(t, cfg.tcp())
	assert.Equal(t, "/run/nebula/info.sock", cfg.Path)
}

// freeTCPAddr returns a loopback address that was free a moment ago, for a test that
// needs a second, distinct address to move an endpoint to. A port the kernel chose for a
// listener that was then closed is the usual way to get one.
func freeTCPAddr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// serveTCP starts an info server on a loopback port the kernel picks, so the test never
// collides with a port in use, and returns the server and the address it bound.
func serveTCP(t *testing.T, h http.Handler) (*InfoServer, string) {
	t.Helper()

	s := NewInfoServer(test.NewLogger(), h)
	require.NoError(t, s.RebindTCP(context.Background(), "127.0.0.1:0"))
	t.Cleanup(s.Stop)
	return s, s.Addr()
}

// TestInfoServesOverTCP: the info API on a TCP address is the same handler and the same
// request rules as on a socket; only the way in differs. The address is how the endpoint
// reports the port the kernel chose.
func TestInfoServesOverTCP(t *testing.T) {
	s, addr := serveTCP(t, stubInfoHandler())
	require.NotEmpty(t, addr)
	assert.Empty(t, s.Path(), "a TCP endpoint has no socket path")

	status, body := httpGetTCP(t, addr, "/v1/whoami?name=alice")
	assert.Equal(t, http.StatusOK, status)
	assert.JSONEq(t, `{"name":"alice"}`, body)

	// The rules the server holds every request to are the same as on a socket.
	status, body = httpGetTCP(t, addr, "/v1/../v1/whoami")
	assert.Equal(t, http.StatusNotFound, status)
	assert.JSONEq(t, `{"error":"no such path /v1/../v1/whoami"}`, body)

	status, _, hdr := httpDoTCP(t, addr, http.MethodPost, "/v1/whoami")
	assert.Equal(t, http.StatusMethodNotAllowed, status)
	assert.Equal(t, http.MethodGet, hdr.Get("Allow"))
}

// TestInfoTCPRebindMovesTheListener: a reload that changes the address moves it, and the
// old address stops answering; a reload that keeps it leaves it where it is. A change of
// port is a change of endpoint, unlike a change of access on a socket.
func TestInfoTCPRebindMovesTheListener(t *testing.T) {
	ctx := context.Background()
	s := NewInfoServer(test.NewLogger(), stubInfoHandler())
	t.Cleanup(s.Stop)

	require.NoError(t, s.RebindTCP(ctx, "127.0.0.1:0"))
	first := s.Addr()
	require.NotEmpty(t, first)

	// Rebinding the same configured address is a no-op: the address the endpoint reports
	// is unchanged. The comparison is of the configured target, which for a kernel-chosen
	// port is the ":0" that was asked for, not the port that came back.
	require.NoError(t, s.RebindTCP(ctx, "127.0.0.1:0"))
	assert.Equal(t, first, s.Addr())

	// A new address binds the new one and gives up the old.
	second := freeTCPAddr(t)
	require.NoError(t, s.RebindTCP(ctx, second))
	require.Equal(t, second, s.Addr())
	require.NotEqual(t, first, second)

	status, _ := httpGetTCP(t, second, "/v1/whoami")
	assert.Equal(t, http.StatusOK, status)

	// The old address no longer answers; a fresh dial is refused.
	_, err := httpGetErr(t, first, "/v1/whoami")
	assert.Error(t, err, "the moved endpoint gave up its old address")
}
