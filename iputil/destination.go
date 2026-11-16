package iputil

import (
	"encoding/binary"
	"net/netip"

	"github.com/slackhq/nebula/overlay/checksum"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// SetDestination rewrites the destination address of an IPv4 or IPv6 packet in
// place and recomputes every checksum that depends on it: the IPv4 header
// checksum, and the TCP/UDP/ICMPv6 upper-layer checksums whose pseudo-header
// includes the destination. UDP over IPv4 may carry a zero checksum (meaning
// "not computed", RFC 768); it is left zero.
//
// Flooding a broadcast or multicast packet to an individual overlay peer needs
// this: the copy handed to each peer must carry that peer's own overlay address
// as the destination, or the peer's firewall (which only accepts its own
// addresses) drops it.
//
// It reports whether the packet was modified. Fragments and packets whose
// transport header cannot be located are left untouched.
func SetDestination(packet []byte, dst netip.Addr) bool {
	if len(packet) < 1 {
		return false
	}
	switch int(packet[0] >> 4) {
	case ipv4.Version:
		return setDestination4(packet, dst.As4())
	case ipv6.Version:
		return setDestination6(packet, dst.As16())
	}
	return false
}

func setDestination4(packet []byte, dst [4]byte) bool {
	if len(packet) < ipv4.HeaderLen {
		return false
	}
	ihl := int(packet[0]&0x0f) << 2
	end := int(binary.BigEndian.Uint16(packet[2:4]))
	if ihl < ipv4.HeaderLen || end < ihl || end > len(packet) {
		return false
	}
	// do not rewrite fragments: the transport checksum cannot be recomputed, and
	// the reassembled datagram would keep the original destination.
	if binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return false
	}

	copy(packet[16:20], dst[:])

	transport, ok := transportExtent(packet[ihl:end], packet[9])
	if ok {
		var csum uint32
		switch packet[9] {
		case IPProtocolTCP:
			if len(transport) >= 20 {
				csum = ipv4PseudoheaderChecksum(packet[12:16], packet[16:20], uint32(packet[9]), uint32(len(transport)))
				writeTransportChecksum(transport, packet[9], csum)
			}
		case IPProtocolUDP:
			if len(transport) >= udpHeaderLen && binary.BigEndian.Uint16(transport[6:8]) != 0 {
				csum = ipv4PseudoheaderChecksum(packet[12:16], packet[16:20], uint32(packet[9]), uint32(len(transport)))
				writeTransportChecksum(transport, packet[9], csum)
			}
		}
	}

	packet[10], packet[11] = 0, 0
	binary.BigEndian.PutUint16(packet[10:], tcpipChecksum(packet[:ihl], 0))
	return true
}

func setDestination6(packet []byte, dst [16]byte) bool {
	if len(packet) < ipv6.HeaderLen {
		return false
	}
	end := ipv6.HeaderLen + int(binary.BigEndian.Uint16(packet[4:6]))
	if end > len(packet) {
		return false
	}

	proto, offset, _, anyFragment, err := IPv6FindUpperProtocol(packet[:end])
	if err != nil || anyFragment || offset >= end {
		return false
	}

	copy(packet[24:40], dst[:])

	transport, ok := transportExtent(packet[offset:end], proto)
	if ok {
		csum := ipv6PseudoheaderChecksum(packet[8:24], packet[24:40], uint32(proto), uint32(len(transport)))
		switch proto {
		case IPProtocolTCP, IPProtocolUDP:
			writeTransportChecksum(transport, proto, csum)
		case IPProtocolICMPv6:
			// ICMPv6's checksum covers the pseudo-header, so a rewritten
			// destination invalidates it (ICMPv4's does not, see setDestination4).
			if len(transport) >= 4 {
				transport[2], transport[3] = 0, 0
				binary.BigEndian.PutUint16(transport[2:], ^checksum.Checksum(transport, fold(csum)))
			}
		}
	}
	return true
}
