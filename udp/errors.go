package udp

import "errors"

// ErrInvalidIPv6RemoteForSocket is returned when an IPv4 socket is asked to send to an IPv6 remote. A lighthouse
// reports every address a peer has, so callers treat it as an expected skip rather than a send failure.
var ErrInvalidIPv6RemoteForSocket = errors.New("listener is IPv4, but writing to IPv6 remote")
