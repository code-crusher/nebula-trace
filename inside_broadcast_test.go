package nebula

import (
	"bytes"
	"net/netip"
	"sync"
	"testing"

	"github.com/flynn/noise"
	"github.com/gaissmai/bart"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/noiseutil"
	"github.com/slackhq/nebula/overlay/batch"
	"github.com/slackhq/nebula/overlay/tio"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/require"
)

// broadcastConn captures encrypted broadcast copies the way relayBatchConn
// does: one record per WriteBatch.
type broadcastConn struct {
	udp.NoopConn
	writes [][]byte
}

func (c *broadcastConn) WriteBatch(bufs [][]byte, addrs []netip.AddrPort) (int, error) {
	for _, b := range bufs {
		c.writes = append(c.writes, bytes.Clone(b))
	}
	return len(bufs), nil
}

// newBroadcastInterface builds an Interface whose hostmap holds two fully
// formed peers (10.0.0.5, 10.0.0.6). Writers feed a broadcastConn so a flood is
// observable. myVpnNetworksTable is deliberately empty: the only packets that
// reach the routing path in these tests are broadcast/multicast ones whose
// broadcastAddrs list is unset, and they must be dropped, not routed.
func newBroadcastInterface(t *testing.T, addrs ...netip.Addr) (*Interface, *broadcastConn) {
	t.Helper()
	l := test.NewLogger()
	conn := &broadcastConn{}
	hostMap := newHostMap(l)

	newPeer := func(vpn, underlay string, id byte) *HostInfo {
		suite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
		cs := noiseutil.NewCipherState(noise.UnsafeNewCipherState(suite, [32]byte{id}, 0), noise.CipherChaChaPoly)
		h := &HostInfo{
			vpnAddrs: []netip.Addr{netip.MustParseAddr(vpn)},
			ConnectionState: &ConnectionState{
				eKey:   cs,
				dKey:   cs,
				window: NewBits(ReplayWindow),
			},
		}
		u := netip.MustParseAddrPort(underlay)
		h.remote.Store(&u)
		hostMap.Hosts[h.vpnAddrs[0]] = h
		return h
	}

	newPeer("10.0.0.5", "198.51.100.1:4242", 1)
	newPeer("10.0.0.6", "198.51.100.2:4242", 2)

	// A lightHouse with no lighthouses and no static hosts. amLighthouse is
	// true so GetOrHandshake never tries to promote a found peer, which would
	// need counters that are zero here.
	lh := &LightHouse{
		amLighthouse: true,
		l:            l,
		addrMap:      make(map[netip.Addr]*RemoteList),
	}
	lh.lighthouses.Store(&[]netip.Addr{})
	lh.staticList.Store(&map[netip.Addr]struct{}{})

	hm := &HandshakeManager{mainHostMap: hostMap, lightHouse: lh, l: l}

	// The broadcast table holds the subnet broadcast of our certificate
	// network, exactly as pki.go computes it. The interface "is" 10.0.0.1/24,
	// so 10.0.0.255 is the local broadcast.
	broadcastTable := new(bart.Lite)
	broadcastTable.Insert(netip.PrefixFrom(netip.MustParseAddr("10.0.0.255"), 32))

	f := &Interface{
		l:                     l,
		hostMap:               hostMap,
		handshakeManager:      hm,
		lightHouse:            lh,
		firewall:              &Firewall{},
		inside:                newFakeDevice(),
		myVpnAddrsTable:       new(bart.Lite),
		myVpnNetworksTable:    new(bart.Lite),
		myBroadcastAddrsTable: broadcastTable,
		writers:               []udp.Conn{conn},
		broadcastAddrs:        addrs,
	}
	f.connectionManager = &connectionManager{
		intf: f, relayUsed: map[uint32]struct{}{}, relayUsedLock: &sync.RWMutex{},
	}
	return f, conn
}

// consumeBroadcast runs a packet through consumeInsidePacket and flushes the
// batch so encrypted writes land on the conn.
func consumeBroadcast(f *Interface, conn *broadcastConn, packet []byte) {
	sb := batch.NewSendBatch(conn, batch.SendBatchCap, 8192)
	f.consumeInsidePacket(tio.Packet{Bytes: packet}, &firewall.ParsedPacket{}, make([]byte, 12), sb, make([]byte, mtu), 0, nil)
	sb.Flush()
}

func TestBroadcastToConfiguredAddrs(t *testing.T) {
	f, conn := newBroadcastInterface(t, netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.0.0.6"))
	broadcast := buildIPv4(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.255"), udpDatagram)
	consumeBroadcast(f, conn, broadcast)

	require.Len(t, conn.writes, 2, "a broadcast to two configured addrs must produce two encrypted copies")
}

func TestBroadcastNotFloodedWithoutConfig(t *testing.T) {
	f, conn := newBroadcastInterface(t)
	// The fallthrough (unconfigured) path drops a broadcast that names no
	// routable destination; nothing may reach the wire.
	broadcast := buildIPv4(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.255"), udpDatagram)
	consumeBroadcast(f, conn, broadcast)

	require.Empty(t, conn.writes, "no broadcast_addrs means no flood")
}

func TestMulticastFloodedToConfiguredAddrs(t *testing.T) {
	f, conn := newBroadcastInterface(t, netip.MustParseAddr("10.0.0.5"))
	// 224.0.0.251 is the mDNS group address.
	multicast := buildIPv4(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("224.0.0.251"), udpDatagram)
	consumeBroadcast(f, conn, multicast)

	require.Len(t, conn.writes, 1, "multicast to one configured addr must produce one encrypted copy")
}
