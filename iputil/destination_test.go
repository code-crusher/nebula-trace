package iputil

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// v4 builds an IPv4 packet with gopacket (independent checksums) whose
// destination the test rewrites.
func v4Dst(t *testing.T, proto layers.IPProtocol) []byte {
	ip := &layers.IPv4{Version: 4, TTL: 64, Id: 0x1234, Protocol: proto,
		SrcIP: net.IPv4(192, 0, 2, 1).To4(), DstIP: net.IPv4(198, 51, 100, 2).To4()}
	var l4 gopacket.SerializableLayer
	switch proto {
	case layers.IPProtocolTCP:
		tcp := &layers.TCP{SrcPort: 49152, DstPort: 443, SYN: true, Window: 65535}
		require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
		l4 = tcp
	case layers.IPProtocolUDP:
		udp := &layers.UDP{SrcPort: 49152, DstPort: 53}
		require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
		l4 = udp
	case layers.IPProtocolICMPv4:
		l4 = &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0), Id: 1, Seq: 1}
	}
	return serialize(t, ip, l4, gopacket.Payload("flood"))
}

// v6 builds an IPv6 packet whose destination the test rewrites.
func v6Dst(t *testing.T, proto layers.IPProtocol) []byte {
	ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: proto,
		SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8:1::2")}
	var l4 gopacket.SerializableLayer
	switch proto {
	case layers.IPProtocolTCP:
		tcp := &layers.TCP{SrcPort: 49152, DstPort: 443, SYN: true, Window: 65535}
		require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
		l4 = tcp
	case layers.IPProtocolUDP:
		udp := &layers.UDP{SrcPort: 49152, DstPort: 53}
		require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
		l4 = udp
	case layers.IPProtocolICMPv6:
		// gopacket cannot compute an ICMPv6 checksum (the layer has no network
		// layer hook), so build the datagram by hand with a valid pseudo-header
		// checksum for the original destination.
		body := []byte{128, 0, 0, 0, 0, 1, 0, 1} // echo request, identifier, sequence
		pkt := make([]byte, 40+len(body))
		pkt[0], pkt[6], pkt[7] = 0x60, 58, 64
		binary.BigEndian.PutUint16(pkt[4:6], uint16(len(body)))
		copy(pkt[8:24], ip.SrcIP)
		copy(pkt[24:40], ip.DstIP)
		copy(pkt[40:], body)
		csum := ipv6PseudoheaderChecksum(pkt[8:24], pkt[24:40], 58, uint32(len(body)))
		binary.BigEndian.PutUint16(pkt[42:44], tcpipChecksum(body, csum))
		return pkt
	}
	return serialize(t, ip, l4, gopacket.Payload("flood"))
}

func dstAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// validFor checks that the transport checksum in pkt is the independent one
// for the given source, destination and transport length. It returns "" when
// valid, or a description of the mismatch.
func validFor(pkt []byte, src, dst netip.Addr, proto uint8, cksumAt int) string {
	body := append([]byte(nil), pkt[40:]...)
	// The checksum field is summed as zero when a checksum is computed.
	body[cksumAt-40], body[cksumAt-39] = 0, 0
	csum := ipv6PseudoheaderChecksum(src.AsSlice(), dst.AsSlice(), uint32(proto), uint32(len(body)))
	want := tcpipChecksum(body, csum)
	got := binary.BigEndian.Uint16(pkt[cksumAt:])
	if want != got {
		return "not valid"
	}
	return ""
}

func TestSetDestination(t *testing.T) {
	dst4 := dstAddr("203.0.113.9")
	dst6 := dstAddr("2001:db8:2::9")

	// verify returns "" if pkt's checksum is valid for the rewritten
	// destination, or an explanation. For TCP and UDP the rewritten checksum is
	// checked by corrupting it and asking SetTransportChecksum (which only
	// handles TCP/UDP) to restore it; ICMPv6's checksum is checked directly.
	recomputed := []struct {
		name   string
		pkt    []byte
		dst    netip.Addr
		verify func(t *testing.T, src netip.Addr, pkt []byte)
	}{
		{"v4 tcp", v4Dst(t, layers.IPProtocolTCP), dst4,
			func(t *testing.T, src netip.Addr, pkt []byte) {
				assertTransportChecksumRestored(t, pkt, 20+16)
			}},
		{"v4 udp", v4Dst(t, layers.IPProtocolUDP), dst4,
			func(t *testing.T, src netip.Addr, pkt []byte) {
				assertTransportChecksumRestored(t, pkt, 20+6)
			}},
		{"v4 icmp", v4Dst(t, layers.IPProtocolICMPv4), dst4,
			func(t *testing.T, src netip.Addr, pkt []byte) {
				// ICMPv4's checksum covers only the message, not the
				// pseudo-header, so it must be byte-for-byte untouched.
				want := binary.BigEndian.Uint16(v4Dst(t, layers.IPProtocolICMPv4)[22:24])
				assert.Equal(t, want, binary.BigEndian.Uint16(pkt[22:24]),
					"icmpv4 checksum must not be recomputed")
			}},
		{"v6 tcp", v6Dst(t, layers.IPProtocolTCP), dst6,
			func(t *testing.T, src netip.Addr, pkt []byte) {
				assertTransportChecksumRestored(t, pkt, 40+16)
			}},
		{"v6 udp", v6Dst(t, layers.IPProtocolUDP), dst6,
			func(t *testing.T, src netip.Addr, pkt []byte) {
				assertTransportChecksumRestored(t, pkt, 40+6)
			}},
		{"v6 icmpv6", v6Dst(t, layers.IPProtocolICMPv6), dst6,
			func(t *testing.T, src netip.Addr, pkt []byte) {
				// SetTransportChecksum deliberately leaves ICMPv6 alone, so
				// check the rewritten checksum directly against the pseudo-header
				// of the new destination.
				msg := validFor(pkt, src, netip.MustParseAddr("2001:db8:2::9"), 58, 40+2)
				assert.Equal(t, "", msg)
			}},
	}
	for _, tt := range recomputed {
		t.Run(tt.name, func(t *testing.T) {
			pkt := append([]byte(nil), tt.pkt...)
			require.True(t, SetDestination(pkt, tt.dst), "rewrite must happen")
			assert.Equal(t, tt.dst.AsSlice(), dstSlice(pkt), "destination must be rewritten")
			src := srcAddr(pkt)
			tt.verify(t, src, pkt)
		})
	}
}

// assertTransportChecksumRestored corrupts the checksum at cksumAt and requires
// SetTransportChecksum to put back exactly the bytes SetDestination produced.
func assertTransportChecksumRestored(t *testing.T, pkt []byte, cksumAt int) {
	t.Helper()
	got := append([]byte(nil), pkt...)
	binary.BigEndian.PutUint16(got[cksumAt:], 0x1234)
	SetTransportChecksum(got)
	assert.Equal(t, pkt, got)
}

func srcAddr(pkt []byte) netip.Addr {
	if pkt[0]>>4 == 4 {
		a, _ := netip.AddrFromSlice(pkt[12:16])
		return a
	}
	a, _ := netip.AddrFromSlice(pkt[8:24])
	return a
}

func dstSlice(pkt []byte) []byte {
	if pkt[0]>>4 == 4 {
		return pkt[16:20]
	}
	return pkt[24:40]
}

func TestSetDestinationICMPv4ChecksumNotRecomputed(t *testing.T) {
	// ICMPv4's checksum covers only the ICMP message, not the pseudo-header, so
	// a destination rewrite leaves it alone.
	pkt := v4Dst(t, layers.IPProtocolICMPv4)
	before := binary.BigEndian.Uint16(pkt[22:24])
	require.True(t, SetDestination(pkt, dstAddr("203.0.113.9")))
	assert.Equal(t, before, binary.BigEndian.Uint16(pkt[22:24]))
}

func TestSetDestinationLeavesUntouchablePacketsAlone(t *testing.T) {
	ip4frag := &layers.IPv4{Version: 4, TTL: 64, Id: 0x1234, Protocol: layers.IPProtocolTCP,
		Flags: layers.IPv4MoreFragments,
		SrcIP: net.IPv4(192, 0, 2, 1).To4(), DstIP: net.IPv4(198, 51, 100, 2).To4()}
	tcp := &layers.TCP{SrcPort: 49152, DstPort: 443, SYN: true, Window: 65535}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip4frag))
	tooShort := v4Dst(t, layers.IPProtocolTCP)[:10]

	untouched := []struct {
		name string
		pkt  []byte
	}{
		{"nil", nil},
		{"v4 fragment", serialize(t, ip4frag, tcp, gopacket.Payload("frag"))},
		{"truncated", tooShort},
	}
	for _, tt := range untouched {
		t.Run(tt.name, func(t *testing.T) {
			want := append([]byte(nil), tt.pkt...)
			assert.False(t, SetDestination(tt.pkt, dstAddr("203.0.113.9")))
			assert.Equal(t, want, tt.pkt)
		})
	}
}
