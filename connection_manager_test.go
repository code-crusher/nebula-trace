package nebula

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay/overlaytest"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// drainLightHouseQueries collects any lighthouse re-queries that have been queued but not yet processed.
func drainLightHouseQueries(lh *LightHouse) []netip.Addr {
	var queried []netip.Addr
	for {
		select {
		case vpnAddr := <-lh.queryChan:
			queried = append(queried, vpnAddr)
		default:
			return queried
		}
	}
}

func newTestLighthouse() *LightHouse {
	lh := &LightHouse{
		l:         test.NewLogger(),
		addrMap:   map[netip.Addr]*RemoteList{},
		queryChan: make(chan netip.Addr, 10),
		// Nothing drains queryChan here, so an 11th query is dropped.
		queryDropped: metrics.NilCounter{},
	}
	lighthouses := []netip.Addr{}
	staticList := map[netip.Addr]struct{}{}

	lh.localAddrsFn = func(*LocalAllowList) []netip.Addr { return nil }
	lh.lighthouses.Store(&lighthouses)
	lh.staticList.Store(&staticList)

	return lh
}

func Test_NewConnectionManagerTest(t *testing.T) {
	l := test.NewLogger()
	//_, tuncidr, _ := net.ParseCIDR("1.1.1.1/24")
	localrange := netip.MustParsePrefix("10.1.1.1/24")
	vpnIp := netip.MustParseAddr("172.1.1.2")
	preferredRanges := []netip.Prefix{localrange}

	// Very incomplete mock objects
	hostMap := newHostMap(l)
	hostMap.preferredRanges.Store(&preferredRanges)

	cs := &CertState{
		initiatingVersion: cert.Version1,
		privateKey:        []byte{},
		v1Cert:            &dummyCert{version: cert.Version1},
		v1Credential:      nil,
	}

	lh := newTestLighthouse()
	ifce := &Interface{
		hostMap:          hostMap,
		inside:           &overlaytest.NoopTun{},
		outside:          &udp.NoopConn{},
		firewall:         &Firewall{},
		lightHouse:       lh,
		pki:              &PKI{},
		handshakeManager: NewHandshakeManager(l, hostMap, lh, &udp.NoopConn{}, defaultHandshakeConfig),
		l:                l,
	}
	ifce.pki.cs.Store(cs)

	// Create manager
	conf := config.NewC(test.NewLogger())
	punchy := NewPunchyFromConfig(test.NewLogger(), conf, nil)
	nc := newConnectionManagerFromConfig(test.NewLogger(), conf, hostMap, punchy)
	nc.intf = ifce
	p := []byte("")
	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)

	// Add an ip we have established a connection w/ to hostmap
	hostinfo := &HostInfo{
		vpnAddrs:      []netip.Addr{vpnIp},
		localIndexId:  1099,
		remoteIndexId: 9901,
	}
	hostinfo.ConnectionState = &ConnectionState{
		myCert: &dummyCert{version: cert.Version1},
	}
	nc.hostMap.unlockedAddHostInfo(hostinfo, ifce)

	// We saw traffic out to vpnIp
	nc.Out(hostinfo)
	nc.In(hostinfo)
	assert.False(t, hostinfo.isPendingDeletion())
	assert.Contains(t, nc.hostMap.Hosts, hostinfo.vpnAddrs[0])
	assert.Contains(t, nc.hostMap.Indexes, hostinfo.localIndexId)
	assert.True(t, hostinfo.sentSinceCheck())
	assert.True(t, (hostinfo.state.Load()&stateIn != 0))

	// Do a traffic check tick, should not be pending deletion but should not have any in/out packets recorded
	nc.doTrafficCheck(hostinfo.localIndexId, p, nb, out, time.Now())
	assert.False(t, hostinfo.isPendingDeletion())
	assert.False(t, hostinfo.sentSinceCheck())
	assert.False(t, (hostinfo.state.Load()&stateIn != 0))

	// Do another traffic check tick, this host should be pending deletion now
	nc.Out(hostinfo)
	assert.True(t, hostinfo.sentSinceCheck())
	nc.doTrafficCheck(hostinfo.localIndexId, p, nb, out, time.Now())
	assert.True(t, hostinfo.isPendingDeletion())
	assert.False(t, hostinfo.sentSinceCheck())
	assert.False(t, (hostinfo.state.Load()&stateIn != 0))
	assert.Contains(t, nc.hostMap.Indexes, hostinfo.localIndexId)
	assert.Contains(t, nc.hostMap.Hosts, hostinfo.vpnAddrs[0])

	// Do a final traffic check tick, the host should now be removed
	nc.doTrafficCheck(hostinfo.localIndexId, p, nb, out, time.Now())
	assert.NotContains(t, nc.hostMap.Hosts, hostinfo.vpnAddrs)
	assert.NotContains(t, nc.hostMap.Indexes, hostinfo.localIndexId)
}

func Test_NewConnectionManagerTest2(t *testing.T) {
	l := test.NewLogger()
	//_, tuncidr, _ := net.ParseCIDR("1.1.1.1/24")
	localrange := netip.MustParsePrefix("10.1.1.1/24")
	vpnIp := netip.MustParseAddr("172.1.1.2")
	preferredRanges := []netip.Prefix{localrange}

	// Very incomplete mock objects
	hostMap := newHostMap(l)
	hostMap.preferredRanges.Store(&preferredRanges)

	cs := &CertState{
		initiatingVersion: cert.Version1,
		privateKey:        []byte{},
		v1Cert:            &dummyCert{version: cert.Version1},
		v1Credential:      nil,
	}

	lh := newTestLighthouse()
	ifce := &Interface{
		hostMap:          hostMap,
		inside:           &overlaytest.NoopTun{},
		outside:          &udp.NoopConn{},
		firewall:         &Firewall{},
		lightHouse:       lh,
		pki:              &PKI{},
		handshakeManager: NewHandshakeManager(l, hostMap, lh, &udp.NoopConn{}, defaultHandshakeConfig),
		l:                l,
	}
	ifce.pki.cs.Store(cs)

	// Create manager
	conf := config.NewC(test.NewLogger())
	punchy := NewPunchyFromConfig(test.NewLogger(), conf, nil)
	nc := newConnectionManagerFromConfig(test.NewLogger(), conf, hostMap, punchy)
	nc.intf = ifce
	p := []byte("")
	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)

	// Add an ip we have established a connection w/ to hostmap
	hostinfo := &HostInfo{
		vpnAddrs:      []netip.Addr{vpnIp},
		localIndexId:  1099,
		remoteIndexId: 9901,
	}
	hostinfo.ConnectionState = &ConnectionState{
		myCert: &dummyCert{version: cert.Version1},
	}
	nc.hostMap.unlockedAddHostInfo(hostinfo, ifce)

	// We saw traffic out to vpnIp
	nc.Out(hostinfo)
	nc.In(hostinfo)
	assert.True(t, (hostinfo.state.Load()&stateIn != 0))
	assert.True(t, hostinfo.sentSinceCheck())
	assert.False(t, hostinfo.isPendingDeletion())
	assert.Contains(t, nc.hostMap.Hosts, hostinfo.vpnAddrs[0])
	assert.Contains(t, nc.hostMap.Indexes, hostinfo.localIndexId)

	// Do a traffic check tick, should not be pending deletion but should not have any in/out packets recorded
	nc.doTrafficCheck(hostinfo.localIndexId, p, nb, out, time.Now())
	assert.False(t, hostinfo.isPendingDeletion())
	assert.False(t, hostinfo.sentSinceCheck())
	assert.False(t, (hostinfo.state.Load()&stateIn != 0))

	// Do another traffic check tick, this host should be pending deletion now
	nc.Out(hostinfo)
	nc.doTrafficCheck(hostinfo.localIndexId, p, nb, out, time.Now())
	assert.True(t, hostinfo.isPendingDeletion())
	assert.False(t, hostinfo.sentSinceCheck())
	assert.False(t, (hostinfo.state.Load()&stateIn != 0))
	assert.Contains(t, nc.hostMap.Indexes, hostinfo.localIndexId)
	assert.Contains(t, nc.hostMap.Hosts, hostinfo.vpnAddrs[0])

	// We saw traffic, should no longer be pending deletion
	nc.In(hostinfo)
	nc.doTrafficCheck(hostinfo.localIndexId, p, nb, out, time.Now())
	assert.False(t, hostinfo.isPendingDeletion())
	assert.False(t, hostinfo.sentSinceCheck())
	assert.False(t, (hostinfo.state.Load()&stateIn != 0))
	assert.Contains(t, nc.hostMap.Indexes, hostinfo.localIndexId)
	assert.Contains(t, nc.hostMap.Hosts, hostinfo.vpnAddrs[0])
}

func Test_NewConnectionManager_CounterLimits(t *testing.T) {
	l := test.NewLogger()
	localrange := netip.MustParsePrefix("10.1.1.1/24")
	vpnIp := netip.MustParseAddr("172.1.1.2")
	preferredRanges := []netip.Prefix{localrange}

	// Very incomplete mock objects
	hostMap := newHostMap(l)
	hostMap.preferredRanges.Store(&preferredRanges)

	cs := &CertState{
		initiatingVersion: cert.Version1,
		privateKey:        []byte{},
		v1Cert:            &dummyCert{version: cert.Version1},
		v1Credential:      nil,
	}

	lh := newTestLighthouse()
	ifce := &Interface{
		hostMap:          hostMap,
		inside:           &overlaytest.NoopTun{},
		outside:          &udp.NoopConn{},
		firewall:         &Firewall{},
		lightHouse:       lh,
		pki:              &PKI{},
		myVpnAddrs:       []netip.Addr{netip.MustParseAddr("172.1.1.1")}, // sorts below vpnIp so shouldSwapPrimary can proceed
		handshakeManager: NewHandshakeManager(l, hostMap, lh, &udp.NoopConn{}, defaultHandshakeConfig),
		l:                l,
	}
	ifce.pki.cs.Store(cs)

	conf := config.NewC(test.NewLogger())
	punchy := NewPunchyFromConfig(test.NewLogger(), conf, nil)
	nc := newConnectionManagerFromConfig(test.NewLogger(), conf, hostMap, punchy)
	nc.intf = ifce

	hostinfo := &HostInfo{
		vpnAddrs:      []netip.Addr{vpnIp},
		localIndexId:  1099,
		remoteIndexId: 9901,
	}
	hostinfo.ConnectionState = &ConnectionState{
		myCert: &dummyCert{version: cert.Version1},
	}
	nc.hostMap.unlockedAddHostInfo(hostinfo, ifce)

	// Below the rehandshake threshold, no handshake is started
	hostinfo.ConnectionState.messageCounter.Store(RehandshakeAfterMessages - 1)
	nc.tryRehandshake(hostinfo)
	assert.Nil(t, ifce.handshakeManager.QueryVpnAddr(vpnIp))

	// A tunnel on its current cert would normally swap to primary
	assert.True(t, nc.shouldSwapPrimary(hostinfo))

	// At the rehandshake threshold, a new handshake is started
	hostinfo.ConnectionState.messageCounter.Store(RehandshakeAfterMessages)
	nc.tryRehandshake(hostinfo)
	assert.NotNil(t, ifce.handshakeManager.QueryVpnAddr(vpnIp))

	// An exhausted tunnel being rolled must never swap back to primary onto its spent key
	assert.False(t, nc.shouldSwapPrimary(hostinfo))

	// Still below the reject limit, the tunnel stays up
	nc.In(hostinfo)
	decision, _, _ := nc.makeTrafficDecision(hostinfo.localIndexId, time.Now())
	assert.Equal(t, tryRehandshake, decision)

	// At the reject limit, the tunnel is deleted locally without a doomed CloseTunnel notify
	hostinfo.ConnectionState.messageCounter.Store(RejectAfterMessages)
	decision, _, _ = nc.makeTrafficDecision(hostinfo.localIndexId, time.Now())
	assert.Equal(t, deleteTunnel, decision)
}

func Test_NewConnectionManager_DisconnectInactive(t *testing.T) {
	l := test.NewLogger()
	localrange := netip.MustParsePrefix("10.1.1.1/24")
	vpnAddrs := []netip.Addr{netip.MustParseAddr("172.1.1.2")}
	preferredRanges := []netip.Prefix{localrange}

	// Very incomplete mock objects
	hostMap := newHostMap(l)
	hostMap.preferredRanges.Store(&preferredRanges)

	cs := &CertState{
		initiatingVersion: cert.Version1,
		privateKey:        []byte{},
		v1Cert:            &dummyCert{version: cert.Version1},
		v1Credential:      nil,
	}

	lh := newTestLighthouse()
	ifce := &Interface{
		hostMap:          hostMap,
		inside:           &overlaytest.NoopTun{},
		outside:          &udp.NoopConn{},
		firewall:         &Firewall{},
		lightHouse:       lh,
		pki:              &PKI{},
		handshakeManager: NewHandshakeManager(l, hostMap, lh, &udp.NoopConn{}, defaultHandshakeConfig),
		l:                l,
	}
	ifce.pki.cs.Store(cs)

	// Create manager
	conf := config.NewC(test.NewLogger())
	conf.Settings["tunnels"] = map[string]any{
		"drop_inactive": true,
	}
	punchy := NewPunchyFromConfig(test.NewLogger(), conf, nil)
	nc := newConnectionManagerFromConfig(test.NewLogger(), conf, hostMap, punchy)
	assert.True(t, nc.dropInactive.Load())
	nc.intf = ifce

	// Add an ip we have established a connection w/ to hostmap
	hostinfo := &HostInfo{
		vpnAddrs:      vpnAddrs,
		localIndexId:  1099,
		remoteIndexId: 9901,
	}
	hostinfo.ConnectionState = &ConnectionState{
		myCert: &dummyCert{version: cert.Version1},
	}
	nc.hostMap.unlockedAddHostInfo(hostinfo, ifce)

	// Do a traffic check tick, in and out should be cleared but should not be pending deletion
	nc.Out(hostinfo)
	nc.In(hostinfo)
	assert.True(t, hostinfo.sentSinceCheck())
	assert.True(t, (hostinfo.state.Load()&stateIn != 0))

	now := time.Now()
	decision, _, _ := nc.makeTrafficDecision(hostinfo.localIndexId, now)
	assert.Equal(t, tryRehandshake, decision)
	assert.Equal(t, now, hostinfo.lastUsed)
	assert.False(t, hostinfo.isPendingDeletion())
	assert.False(t, hostinfo.sentSinceCheck())
	assert.False(t, (hostinfo.state.Load()&stateIn != 0))

	decision, _, _ = nc.makeTrafficDecision(hostinfo.localIndexId, now.Add(time.Second*5))
	assert.Equal(t, doNothing, decision)
	assert.Equal(t, now, hostinfo.lastUsed)
	assert.False(t, hostinfo.isPendingDeletion())
	assert.False(t, hostinfo.sentSinceCheck())
	assert.False(t, (hostinfo.state.Load()&stateIn != 0))

	// Do another traffic check tick, should still not be pending deletion
	decision, _, _ = nc.makeTrafficDecision(hostinfo.localIndexId, now.Add(time.Second*10))
	assert.Equal(t, doNothing, decision)
	assert.Equal(t, now, hostinfo.lastUsed)
	assert.False(t, hostinfo.isPendingDeletion())
	assert.False(t, hostinfo.sentSinceCheck())
	assert.False(t, (hostinfo.state.Load()&stateIn != 0))
	assert.Contains(t, nc.hostMap.Indexes, hostinfo.localIndexId)
	assert.Contains(t, nc.hostMap.Hosts, hostinfo.vpnAddrs[0])

	// Finally advance beyond the inactivity timeout
	decision, _, _ = nc.makeTrafficDecision(hostinfo.localIndexId, now.Add(time.Minute*10))
	assert.Equal(t, closeTunnel, decision)
	assert.Equal(t, now, hostinfo.lastUsed)
	assert.False(t, hostinfo.isPendingDeletion())
	assert.False(t, hostinfo.sentSinceCheck())
	assert.False(t, (hostinfo.state.Load()&stateIn != 0))
	assert.Contains(t, nc.hostMap.Indexes, hostinfo.localIndexId)
	assert.Contains(t, nc.hostMap.Hosts, hostinfo.vpnAddrs[0])
}

// Check if we can disconnect the peer.
// Validate if the peer's certificate is invalid (expired, etc.)
// Disconnect only if disconnectInvalid: true is set.
func Test_NewConnectionManagerTest_DisconnectInvalid(t *testing.T) {
	now := time.Now()
	l := test.NewLogger()

	vpncidr := netip.MustParsePrefix("172.1.1.1/24")
	localrange := netip.MustParsePrefix("10.1.1.1/24")
	vpnIp := netip.MustParseAddr("172.1.1.2")
	preferredRanges := []netip.Prefix{localrange}
	hostMap := newHostMap(l)
	hostMap.preferredRanges.Store(&preferredRanges)

	// Generate keys for CA and peer's cert.
	pubCA, privCA, _ := ed25519.GenerateKey(rand.Reader)
	tbs := &cert.TBSCertificate{
		Version:   1,
		Name:      "ca",
		IsCA:      true,
		NotBefore: now,
		NotAfter:  now.Add(1 * time.Hour),
		PublicKey: pubCA,
	}

	caCert, err := tbs.Sign(nil, cert.Curve_CURVE25519, privCA)
	require.NoError(t, err)
	ncp := cert.NewCAPool()
	require.NoError(t, ncp.AddCA(caCert))

	pubCrt, _, _ := ed25519.GenerateKey(rand.Reader)
	tbs = &cert.TBSCertificate{
		Version:   1,
		Name:      "host",
		Networks:  []netip.Prefix{vpncidr},
		NotBefore: now,
		NotAfter:  now.Add(60 * time.Second),
		PublicKey: pubCrt,
	}
	peerCert, err := tbs.Sign(caCert, cert.Curve_CURVE25519, privCA)
	require.NoError(t, err)

	cachedPeerCert, err := ncp.VerifyCertificate(now.Add(time.Second), peerCert)

	cs := &CertState{
		privateKey:   []byte{},
		v1Cert:       &dummyCert{},
		v1Credential: nil,
	}

	lh := newTestLighthouse()
	ifce := &Interface{
		hostMap:          hostMap,
		inside:           &overlaytest.NoopTun{},
		outside:          &udp.NoopConn{},
		firewall:         &Firewall{},
		lightHouse:       lh,
		handshakeManager: NewHandshakeManager(l, hostMap, lh, &udp.NoopConn{}, defaultHandshakeConfig),
		l:                l,
		pki:              &PKI{},
	}
	ifce.pki.cs.Store(cs)
	ifce.pki.caPool.Store(ncp)
	ifce.disconnectInvalid.Store(true)

	// Create manager
	conf := config.NewC(test.NewLogger())
	punchy := NewPunchyFromConfig(test.NewLogger(), conf, nil)
	nc := newConnectionManagerFromConfig(test.NewLogger(), conf, hostMap, punchy)
	nc.intf = ifce
	ifce.connectionManager = nc

	hostinfo := &HostInfo{
		vpnAddrs: []netip.Addr{vpnIp},
		ConnectionState: &ConnectionState{
			myCert:   &dummyCert{},
			peerCert: cachedPeerCert,
		},
	}
	nc.hostMap.unlockedAddHostInfo(hostinfo, ifce)

	// Move ahead 45s.
	// Check if to disconnect with invalid certificate.
	// Should be alive.
	nextTick := now.Add(45 * time.Second)
	invalid := nc.isInvalidCertificate(nextTick, hostinfo)
	assert.False(t, invalid)

	// Move ahead 61s.
	// Check if to disconnect with invalid certificate.
	// Should be disconnected.
	nextTick = now.Add(61 * time.Second)
	invalid = nc.isInvalidCertificate(nextTick, hostinfo)
	assert.True(t, invalid)
}

// newStaleRemoteFixture builds a connection manager, lighthouse, and a primary tunnel whose remote is set to a
// direct underlay address. The peer is only reachable via a relay after that direct path dies (issue #1748).
func newStaleRemoteFixture(t *testing.T, remoteFallbackAfter int) (*connectionManager, *LightHouse, *HostInfo) {
	t.Helper()
	l := test.NewLogger()
	localrange := netip.MustParsePrefix("10.1.1.1/24")
	vpnIp := netip.MustParseAddr("172.1.1.2")
	preferredRanges := []netip.Prefix{localrange}

	hostMap := newHostMap(l)
	hostMap.preferredRanges.Store(&preferredRanges)

	cs := &CertState{
		initiatingVersion: cert.Version1,
		privateKey:        []byte{},
		v1Cert:            &dummyCert{version: cert.Version1},
		v1Credential:      nil,
	}

	lh := newTestLighthouse()
	ifce := &Interface{
		hostMap:          hostMap,
		inside:           &overlaytest.NoopTun{},
		outside:          &udp.NoopConn{},
		firewall:         &Firewall{},
		lightHouse:       lh,
		pki:              &PKI{},
		handshakeManager: NewHandshakeManager(l, hostMap, lh, &udp.NoopConn{}, defaultHandshakeConfig),
		l:                l,
	}
	ifce.pki.cs.Store(cs)

	conf := config.NewC(test.NewLogger())
	if remoteFallbackAfter > 0 {
		conf.Settings["timers"] = map[string]any{"remote_fallback_after": remoteFallbackAfter}
	}
	punchy := NewPunchyFromConfig(test.NewLogger(), conf, nil)
	nc := newConnectionManagerFromConfig(test.NewLogger(), conf, hostMap, punchy)
	nc.intf = ifce
	ifce.connectionManager = nc

	hostinfo := &HostInfo{
		vpnAddrs:      []netip.Addr{vpnIp},
		localIndexId:  1099,
		remoteIndexId: 9901,
	}
	hostinfo.ConnectionState = &ConnectionState{
		myCert: &dummyCert{version: cert.Version1},
	}
	hostinfo.remotes = lh.QueryCache([]netip.Addr{vpnIp})
	hostinfo.SetRemote(netip.MustParseAddrPort("198.51.100.2:4242"))
	nc.hostMap.unlockedAddHostInfo(hostinfo, ifce)

	return nc, lh, hostinfo
}

// A primary tunnel pinned to a dead direct remote but kept alive by relay traffic must clear the stale remote and
// re-handshake once enough ticks pass with outbound traffic and no direct inbound traffic, so outbound packets fall
// back to the relay instead of being blackholed (issue #1748).
func Test_NewConnectionManager_StaleRemoteFallsBackToRelay(t *testing.T) {
	nc, lh, hostinfo := newStaleRemoteFixture(t, 0)

	// Relay traffic keeps the tunnel alive: inbound arrives, but never directly. The counter accumulates across
	// consecutive ticks; each makeTrafficDecision is one connection-manager tick.
	fallbackAfter := int(nc.remoteFallbackAfter)
	for i := 1; i < fallbackAfter; i++ {
		nc.Out(hostinfo)
		nc.In(hostinfo) // relayed inbound
		decision, _, _ := nc.makeTrafficDecision(hostinfo.localIndexId, time.Now())
		assert.Equal(t, tryRehandshake, decision, "the tunnel stays up but keeps trying to rehandshake")
		assert.True(t, hostinfo.GetRemote().IsValid(), "the remote is only cleared once the threshold is reached")
		assert.Equal(t, int32(i), hostinfo.remoteCheckCounter.Load(), "the counter tracks consecutive ticks")
	}

	// Drive the crossing tick through doTrafficCheck, which runs the clearRemote action: the stale remote is dropped,
	// the lighthouse is re-queried, and a fresh handshake is started so outbound falls back to the relay until the
	// peer teaches us a working direct address.
	nc.Out(hostinfo)
	nc.In(hostinfo)
	nc.doTrafficCheck(hostinfo.localIndexId, []byte(""), make([]byte, 12, 12), make([]byte, mtu), time.Now())
	assert.Zero(t, hostinfo.remoteCheckCounter.Load(), "the counter resets after the fallback fires")
	assert.False(t, hostinfo.GetRemote().IsValid(), "the action cleared the stale remote")
	assert.Equal(t, netip.MustParseAddrPort("198.51.100.2:4242"), hostinfo.lastRoamRemote, "the old remote is preserved for roam suppression")
	assert.Contains(t, drainLightHouseQueries(lh), hostinfo.vpnAddrs[0], "the action re-queried the lighthouse")

	// A direct packet re-pins the remote (as handleHostRoaming would) and proves the direct path healthy again:
	// outbound with direct inbound traffic no longer clears anything.
	hostinfo.SetRemote(netip.MustParseAddrPort("198.51.100.2:4242"))
	nc.Out(hostinfo)
	nc.InDirect(hostinfo)
	decision, _, _ := nc.makeTrafficDecision(hostinfo.localIndexId, time.Now())
	assert.Equal(t, tryRehandshake, decision, "a direct packet re-established the remote, the tunnel is healthy again")
	assert.True(t, hostinfo.GetRemote().IsValid())
}

// A tunnel that receives a direct inbound packet resets the stale-remote counter: the direct path is healthy and
// nothing should be cleared.
func Test_NewConnectionManager_StaleRemoteDirectTrafficResets(t *testing.T) {
	nc, lh, hostinfo := newStaleRemoteFixture(t, 0)

	nc.Out(hostinfo)
	nc.In(hostinfo)
	nc.makeTrafficDecision(hostinfo.localIndexId, time.Now())
	assert.Equal(t, int32(1), hostinfo.remoteCheckCounter.Load(), "a relay-only tick with outbound traffic increments the counter")

	// A direct packet arrives; the counter resets and no clearing happens.
	nc.Out(hostinfo)
	nc.InDirect(hostinfo)
	decision, _, _ := nc.makeTrafficDecision(hostinfo.localIndexId, time.Now())
	assert.Equal(t, tryRehandshake, decision, "direct inbound traffic keeps the remote pinned")
	assert.Zero(t, hostinfo.remoteCheckCounter.Load(), "a direct inbound packet resets the stale-remote counter")
	assert.True(t, hostinfo.GetRemote().IsValid())
	assert.Empty(t, drainLightHouseQueries(lh), "no lighthouse query is needed when the direct path is healthy")
}

// The stale-remote fallback is only armed when outbound traffic exists: a tunnel that only receives relay traffic
// with nothing to send has no blackholed outbound path and must never clear its remote.
func Test_NewConnectionManager_StaleRemoteRequiresOutboundTraffic(t *testing.T) {
	nc, lh, hostinfo := newStaleRemoteFixture(t, 0)

	for i := 0; i < int(nc.remoteFallbackAfter)+2; i++ {
		nc.In(hostinfo) // relayed inbound only
		decision, _, _ := nc.makeTrafficDecision(hostinfo.localIndexId, time.Now())
		assert.Equal(t, tryRehandshake, decision)
		assert.True(t, hostinfo.GetRemote().IsValid(), "no outbound traffic, the remote must stay pinned")
	}
	assert.Empty(t, drainLightHouseQueries(lh))
}

type dummyCert struct {
	version        cert.Version
	curve          cert.Curve
	groups         []string
	isCa           bool
	issuer         string
	name           string
	networks       []netip.Prefix
	notAfter       time.Time
	notBefore      time.Time
	publicKey      []byte
	signature      []byte
	unsafeNetworks []netip.Prefix
}

func (d *dummyCert) Version() cert.Version {
	return d.version
}

func (d *dummyCert) Curve() cert.Curve {
	return d.curve
}

func (d *dummyCert) Groups() []string {
	return d.groups
}

func (d *dummyCert) IsCA() bool {
	return d.isCa
}

func (d *dummyCert) Issuer() string {
	return d.issuer
}

func (d *dummyCert) Name() string {
	return d.name
}

func (d *dummyCert) Networks() []netip.Prefix {
	return d.networks
}

func (d *dummyCert) NotAfter() time.Time {
	return d.notAfter
}

func (d *dummyCert) NotBefore() time.Time {
	return d.notBefore
}

func (d *dummyCert) PublicKey() []byte {
	return d.publicKey
}

func (d *dummyCert) MarshalPublicKeyPEM() []byte {
	return cert.MarshalPublicKeyToPEM(d.curve, d.publicKey)
}

func (d *dummyCert) Signature() []byte {
	return d.signature
}

func (d *dummyCert) UnsafeNetworks() []netip.Prefix {
	return d.unsafeNetworks
}

func (d *dummyCert) MarshalForHandshakes() ([]byte, error) {
	return nil, nil
}

func (d *dummyCert) Sign(curve cert.Curve, key []byte) error {
	return nil
}

func (d *dummyCert) CheckSignature(key []byte) bool {
	return true
}

func (d *dummyCert) Expired(t time.Time) bool {
	return false
}

func (d *dummyCert) CheckRootConstraints(signer cert.Certificate) error {
	return nil
}

func (d *dummyCert) VerifyPrivateKey(curve cert.Curve, key []byte) error {
	return nil
}

func (d *dummyCert) String() string {
	return ""
}

func (d *dummyCert) Marshal() ([]byte, error) {
	return nil, nil
}

func (d *dummyCert) MarshalPEM() ([]byte, error) {
	return nil, nil
}

func (d *dummyCert) Fingerprint() (string, error) {
	return "", nil
}

func (d *dummyCert) MarshalJSON() ([]byte, error) {
	return nil, nil
}

func (d *dummyCert) Copy() cert.Certificate {
	return d
}
