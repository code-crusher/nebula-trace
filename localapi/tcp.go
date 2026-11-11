package localapi

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// tcpTransport is the info API on a TCP address instead of a local socket. It is the
// second half of what the issue behind this endpoint asks for: a socket is reachable by
// whoever can reach the filesystem, a TCP address on the node's nebula address is
// reachable by peers the Nebula firewall admits, and the firewall, not a mode bit, is
// what restricts it.
//
// There is no node to identify, remove, or chmod, and no access to apply: the address is
// the whole of the access control. The methods below say so, and the endpoint lifecycle
// treats a TCP endpoint as always still there and never changeable in place, which is
// what makes a reload that changes its address move it.
type tcpTransport struct{}

// isTCPTransport reports whether t is the TCP transport, which the endpoint lifecycle
// asks to tell an address from a socket path when deciding whether a reload's target
// names the endpoint it is already serving.
func isTCPTransport(t transport) bool {
	_, ok := t.(tcpTransport)
	return ok
}

func (tcpTransport) listen(target string, _ Access) (net.Listener, error) {
	return net.Listen("tcp", target)
}

// identify has nothing to identify: an address cannot be removed from under the daemon
// the way a socket node can, so an endpoint on it is always still there. true with the
// zero id keeps rebindLocked from mistaking a bound address for a socket that was taken
// away.
func (tcpTransport) identify(string) (socketID, bool) { return socketID{}, true }

func (tcpTransport) remove(string, socketID) {}

// sameTarget compares the addresses as the configs spell them, normalised by
// parseListenAddr when the config is read, so "127.0.0.1:8080" and "[::1]:8080" are told
// apart while "127.0.0.1:8080" and "127.0.0.1:08080" name one address.
func (tcpTransport) sameTarget(a, b string) bool {
	aa, errA := netip.ParseAddrPort(a)
	bb, errB := netip.ParseAddrPort(b)
	if errA != nil || errB != nil {
		return a == b
	}
	return aa == bb
}

// accessChanged is never true in practice: a TCP endpoint has no mode or group, so it is
// bound with the zero Access and RebindTCP passes the zero Access, and the two compare
// equal. The comparison is still the right question to ask, and it keeps the endpoint
// lifecycle honest if a future TCP form ever carries an access of its own.
func (tcpTransport) accessChanged(old, acc Access) bool { return old != acc }

// applyAccess cannot change a TCP endpoint's access, because it has none to change. It
// is never reached for an unchanged address: the endpoint is bound with the zero Access
// and the config's Access is discarded when a TCP listen is chosen, so accessChanged
// stays false.
func (tcpTransport) applyAccess(string, Access) error { return errAccessFixed }

// InfoListenKey is the config key that names a TCP address for the info API, in place of
// InfoSocketKey. It is the remote half of the endpoint: the address is bound as given and
// reached over the Nebula interface, where the firewall's inbound rules decide who may
// connect. Exactly one of InfoSocketKey and InfoListenKey must be set when the API is
// enabled.
const InfoListenKey = "local_api.info.listen"

// parseListenAddr checks a configured InfoListenKey value: one address and a port, never a
// wildcard.
//
// A wildcard would serve the API on every interface the host has, the public one
// included, where the Nebula firewall does not apply; an operator who wants the API on the
// overlay names the node's nebula address, and one who wants it on the host alone names a
// loopback address. The host must be an IP literal rather than a name, because a name is
// resolved at bind time and could widen what is served without the config saying so. Port
// 0 is allowed and lets the kernel choose, which is how a test asks for a free port; a
// reload that keeps it re-binds to a new port, which is why an operator does not use it.
func parseListenAddr(raw string) (string, error) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return "", fmt.Errorf("%s must be a host:port address, got %q: %w", InfoListenKey, raw, err)
	}

	if host == "" {
		return "", fmt.Errorf("%s must name one address, not a wildcard: %q serves every interface, where the Nebula firewall does not apply; name the node's nebula address or a loopback address", InfoListenKey, raw)
	}

	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "", fmt.Errorf("%s must name an IP address, not the name %q; a name is resolved at bind time and could widen the address served", InfoListenKey, host)
	}
	if ip.IsUnspecified() {
		return "", fmt.Errorf("%s must name one address, not the wildcard %q, which serves every interface; name the node's nebula address or a loopback address", InfoListenKey, host)
	}

	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", fmt.Errorf("%s must name a port, got %q in %q", InfoListenKey, port, raw)
	}

	// Normalised, so that "10.42.0.1:08080" and "10.42.0.1:8080" compare equal and a
	// reload that respelled the port is not mistaken for a move.
	return net.JoinHostPort(ip.String(), strconv.FormatUint(p, 10)), nil
}
