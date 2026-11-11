package nebula

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/slackhq/nebula/localapi"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// infoGet sends one GET to the handler and returns the status and body.
func infoGet(t *testing.T, h http.Handler, target string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec.Code, rec.Body.String()
}

// TestInfoHandlerServesIdentity: the four routes answer what the identity command
// answers, through the one lookup, and a connection's remote address passes through.
func TestInfoHandlerServesIdentity(t *testing.T) {
	f, peerCert := identityFixture(t)
	h := infoHandler(f)

	status, body := infoGet(t, h, "/v1/identity")
	require.Equal(t, http.StatusOK, status, body)
	var me hostIdentity
	require.NoError(t, json.Unmarshal([]byte(body), &me))
	assert.Equal(t, "me", me.Name)
	assert.NotContains(t, body, `"pem"`, "the certificate is its own resource")

	for _, target := range []string{"/v1/identity/10.0.0.2", "/v1/identity/10.0.0.2:4242", "/v1/identity/[::ffff:10.0.0.2]:4242"} {
		status, body := infoGet(t, h, target)
		require.Equal(t, http.StatusOK, status, "%s: %s", target, body)
		var peer hostIdentity
		require.NoError(t, json.Unmarshal([]byte(body), &peer))
		assert.Equal(t, "peer", peer.Name, target)
	}

	want, err := peerCert.MarshalPEM()
	require.NoError(t, err)
	status, body = infoGet(t, h, "/v1/identity/10.0.0.2:4242/pem")
	require.Equal(t, http.StatusOK, status, body)
	var raw certPEM
	require.NoError(t, json.Unmarshal([]byte(body), &raw))
	assert.Equal(t, string(want), raw.PEM)

	own, err := ownCertificate(f.pki.getCertState()).MarshalPEM()
	require.NoError(t, err)
	status, body = infoGet(t, h, "/v1/identity/pem")
	require.Equal(t, http.StatusOK, status, body)
	require.NoError(t, json.Unmarshal([]byte(body), &raw))
	assert.Equal(t, string(own), raw.PEM)

	// The same bytes -json prints over ssh, newline included, and -pretty's layout.
	status, compact := infoGet(t, h, "/v1/identity/10.0.0.2/pem")
	require.Equal(t, http.StatusOK, status)
	//nolint:testifylint // the exact bytes are what is under test
	assert.Equal(t, `{"pem":`+string(mustJSON(t, string(want)))+"}\n", compact)
	status, pretty := infoGet(t, h, "/v1/identity/10.0.0.2/pem?pretty")
	require.Equal(t, http.StatusOK, status)
	//nolint:testifylint // the layout is what is under test
	assert.Equal(t, "{\n    \"pem\": "+string(mustJSON(t, string(want)))+"\n}\n", pretty)
	_, off := infoGet(t, h, "/v1/identity/10.0.0.2/pem?pretty=false")
	assert.Equal(t, compact, off)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

// TestInfoHandlerStatusCodes: the asking being wrong is a 400, the thing asked about
// not being there a 404, a path not served a 404 that says what is, and the empty
// address a program failed to fill in is a path not served, never this node.
func TestInfoHandlerStatusCodes(t *testing.T) {
	f, _ := identityFixture(t)
	h := infoHandler(f)

	for _, tc := range []struct {
		target string
		status int
		body   string
	}{
		{"/v1/identity/10.0.0.9", http.StatusNotFound, `{"error":"No active tunnel for vpn addr: 10.0.0.9"}`},
		{"/v1/identity/10.0.0.3/pem", http.StatusNotFound, `{"error":"No active tunnel for vpn addr: 10.0.0.3"}`},
		{"/v1/identity/9.9.9.9", http.StatusNotFound, `{"error":"No active tunnel for vpn addr: 9.9.9.9"}`},
		{"/v1/identity/not-an-address", http.StatusBadRequest, `{"error":"The provided vpn addr could not be parsed: not-an-address"}`},
		{"/v1/identity?nope=1", http.StatusBadRequest, `{"error":"unknown parameter \"nope\"; the info API takes pretty alone"}`},
		{"/v1/identity?pretty=maybe", http.StatusBadRequest, `{"error":"pretty: expected a boolean, got \"maybe\""}`},
		{"/v1/identity?pretty&pretty", http.StatusBadRequest, `{"error":"parameter \"pretty\" was given more than once"}`},
		{"/v1/identity?pretty=%zz", http.StatusBadRequest, `{"error":"malformed query string: invalid URL escape \"%zz\""}`},
	} {
		status, body := infoGet(t, h, tc.target)
		assert.Equal(t, tc.status, status, tc.target)
		assert.JSONEq(t, tc.body, body, tc.target)
	}

	for _, target := range []string{"/", "/v1", "/v1/", "/v1/identity/", "/v1/identity/10.0.0.2/", "/v1/identity/10.0.0.2/pem/x", "/v1/identity/10.0.0.2/raw", "/v1/list-hostmap", "/v1/print-tunnel/10.0.0.2", "/v2/identity"} {
		status, body := infoGet(t, h, target)
		assert.Equal(t, http.StatusNotFound, status, target)
		assert.Contains(t, body, "no such path", target)
		assert.Contains(t, body, "/v1/identity", "%s: the miss says what is served", target)
	}

	status, body := infoGet(t, infoHandler(&Interface{pki: &PKI{}}), "/v1/identity")
	assert.Equal(t, http.StatusInternalServerError, status)
	assert.JSONEq(t, `{"error":"No certificate is loaded"}`, body)
}

// TestInfoHandlerAgreesWithTheCommand: the handler and the identity command are one
// lookup and one shape, so a program reading either sees the same identity.
func TestInfoHandlerAgreesWithTheCommand(t *testing.T) {
	f, _ := identityFixture(t)

	_, body := infoGet(t, infoHandler(f), "/v1/identity/10.0.0.2")
	fromCommand := mustJSON(t, identity(t, f, "10.0.0.2").Payload())
	assert.JSONEq(t, string(fromCommand), body)

	_, body = infoGet(t, infoHandler(f), "/v1/identity")
	fromCommand = mustJSON(t, identity(t, f).Payload())
	assert.JSONEq(t, string(fromCommand), body)
}

// TestInfoHandlerOverTCP is the issue's remote half end to end: the daemon's own handler,
// served by localapi.InfoServer on a TCP address, answers a peer the way the local socket
// does, and holds the same read-only rules. The address is the whole of the access
// control; the Nebula firewall's inbound rules decide who may reach it, so this is what a
// curl from another host on the overlay sees.
func TestInfoHandlerOverTCP(t *testing.T) {
	f, _ := identityFixture(t)

	srv := localapi.NewInfoServer(test.NewLogger(), infoHandler(f))
	require.NoError(t, srv.RebindTCP(context.Background(), "127.0.0.1:0"))
	t.Cleanup(srv.Stop)

	base := "http://" + srv.Addr()
	res, err := http.Get(base + "/v1/identity/10.0.0.2")
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Equal(t, "application/json", res.Header.Get("Content-Type"))

	var peer hostIdentity
	require.NoError(t, json.NewDecoder(res.Body).Decode(&peer))
	assert.Equal(t, "peer", peer.Name)
	assert.Equal(t, []string{"web", "db"}, peer.Groups)

	// The read-only rule holds on the address as on the socket: a program cannot use it
	// to act, only to ask.
	req, err := http.NewRequest(http.MethodPost, base+"/v1/identity", nil)
	require.NoError(t, err)
	res, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, res.StatusCode)
	assert.Equal(t, http.MethodGet, res.Header.Get("Allow"))
}
