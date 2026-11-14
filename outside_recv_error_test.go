package nebula

import (
	"net/netip"
	"testing"

	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newRecvErrorRelayFixture builds an interface with a live tunnel to a relay host that relays for a
// target. A packet sent over that relay carries relay.RemoteIndex, so that is the index a peer that
// cannot process it mirrors back in a recv_error.
func newRecvErrorRelayFixture(t *testing.T) (*Interface, *HostInfo, *Relay, netip.AddrPort) {
	t.Helper()
	l := test.NewLogger()
	hm := newHostMap(l)
	lh := newTestLighthouse()
	hsm := NewHandshakeManager(l, hm, lh, nil, defaultHandshakeConfig)
	f := &Interface{
		hostMap:               hm,
		lightHouse:            lh,
		handshakeManager:      hsm,
		l:                     l,
		acceptRecvErrorConfig: recvErrorAlways,
		messageMetrics:        newMessageMetricsOnlyRecvError(),
	}
	hsm.f = f

	relayAddr := netip.MustParseAddr("10.128.0.128")
	target := netip.MustParseAddr("10.128.0.2")
	relayRemote := netip.MustParseAddrPort("192.0.2.128:4242")

	relayHI := &HostInfo{
		vpnAddrs:      []netip.Addr{relayAddr},
		localIndexId:  2,
		remoteIndexId: 200,
		relayState:    RelayState{relayForByAddr: map[netip.Addr]*Relay{}, relayForByIdx: map[uint32]*Relay{}},
	}
	u := relayRemote
	relayHI.remote.Store(&u)
	hm.unlockedAddHostInfo(relayHI, f)

	idx, err := AddRelay(l, relayHI, hm, target, nil, TerminalType, Requested)
	require.NoError(t, err)
	require.True(t, relayHI.relayState.CompleteRelayByIP(target, 302))

	r, ok := relayHI.relayState.QueryRelayForByIdx(idx)
	require.True(t, ok)
	return f, relayHI, r, relayRemote
}

// TestHandleRecvError_RelayIndex verifies a recv_error carrying a relay index is attributed to the
// relay instead of being dropped as an unknown index. The relay is marked Disestablished so the
// relay manager rebuilds it, while the healthy direct tunnel to the relay host is left alone.
func TestHandleRecvError_RelayIndex(t *testing.T) {
	f, relayHI, relay, relayRemote := newRecvErrorRelayFixture(t)

	f.handleRecvError(relayRemote, &header.H{Type: header.RecvError, RemoteIndex: relay.RemoteIndex})

	got, ok := relayHI.relayState.QueryRelayForByIdx(relay.LocalIndex)
	require.True(t, ok)
	assert.Equal(t, Disestablished, got.State, "the relay should be marked disestablished")
	assert.Same(t, relayHI, f.hostMap.QueryVpnAddr(relayHI.vpnAddrs[0]), "the tunnel to the relay must survive")
}

// TestHandleRecvError_RelayIndexSpoofGuard verifies the spoof guard covers the relay path too, so a
// third party cannot tear down a relay by guessing its index.
func TestHandleRecvError_RelayIndexSpoofGuard(t *testing.T) {
	f, relayHI, relay, _ := newRecvErrorRelayFixture(t)

	spoofed := netip.MustParseAddrPort("198.51.100.99:4242")
	f.handleRecvError(spoofed, &header.H{Type: header.RecvError, RemoteIndex: relay.RemoteIndex})

	got, _ := relayHI.relayState.QueryRelayForByIdx(relay.LocalIndex)
	assert.Equal(t, Established, got.State, "a recv_error from an unexpected address must not touch the relay")
}

// TestHandleRecvError_UnknownRelayIndex verifies an index no relay has claimed still falls through
// to the existing behavior: nothing is found and nothing changes.
func TestHandleRecvError_UnknownRelayIndex(t *testing.T) {
	f, relayHI, relay, relayRemote := newRecvErrorRelayFixture(t)

	f.handleRecvError(relayRemote, &header.H{Type: header.RecvError, RemoteIndex: relay.RemoteIndex + 1000})

	got, _ := relayHI.relayState.QueryRelayForByIdx(relay.LocalIndex)
	assert.Equal(t, Established, got.State)
}
