package localapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
)

// transport is how an endpoint reaches its clients: the platform's local socket, or a
// TCP address on one of the host's interfaces. The lifecycle below is the same either
// way; only binding, and what "the same endpoint" and "the access changed" mean, differ.
type transport interface {
	// listen binds the endpoint at target with acc.
	listen(target string, acc Access) (net.Listener, error)

	// identify returns the identity of whatever listen created at target, and false when
	// there is nothing to identify. A transport with nothing to identify returns true and
	// the zero id, so that rebindLocked sees the endpoint as still there; see
	// platform_windows.go's identifySocket.
	identify(target string) (socketID, bool)

	// remove gives up the node listen created at target, if the transport has one.
	remove(target string, id socketID)

	// sameTarget reports whether two configured targets name one endpoint.
	sameTarget(a, b string) bool

	// accessChanged reports whether acc differs from the access the endpoint was bound
	// with.
	accessChanged(old, acc Access) bool

	// applyAccess changes the access of the endpoint at target in place, or returns
	// errAccessFixed.
	applyAccess(target string, acc Access) error
}

// socketTransport is the platform's local socket: a unix socket, or a named pipe on
// windows. The nil transport means this one, so the two servers that predate the TCP
// transport need not say so.
type socketTransport struct{}

func (socketTransport) listen(target string, acc Access) (net.Listener, error) {
	return listen(target, acc)
}
func (socketTransport) identify(target string) (socketID, bool) { return identifySocket(target) }
func (socketTransport) remove(target string, id socketID)       { removeSocket(target, id) }
func (socketTransport) sameTarget(a, b string) bool             { return samePath(a, b) }
func (socketTransport) accessChanged(old, acc Access) bool      { return accessChanged(old, acc) }
func (socketTransport) applyAccess(target string, acc Access) error {
	return applyAccess(target, acc)
}

// endpoint is for managing the lifecycle of local API endpoints.
type endpoint struct {
	l *slog.Logger

	// name is what the endpoint is called in its own log lines and errors, so the two
	// read apart.
	name string

	// t is how the endpoint currently reaches its clients: the transport its live bind
	// used. nil before the first bind, and read through transport().
	t transport

	mu sync.Mutex

	// closer stops the serving when closed: the listener itself, or the server that owns
	// it. It is nil while the endpoint is stopped, which is what stopped means here.
	closer     io.Closer
	path       string
	addr       string
	access     Access
	cancelStop func() bool

	// id identifies the node listen created at path, so a reload can tell whether the
	// socket is still there and Stop whether the node it would unlink is still ours.
	id socketID
}

// socketID identifies a socket's node on the filesystem, by device and inode on unix.
// The zero value is no identity: a platform with no node to identify, or one that could
// not be read, and removeSocket then unlinks without looking.
type socketID struct {
	dev, ino uint64
}

// Path returns the socket path currently being served, or "" when stopped or served over
// TCP; see Addr.
func (e *endpoint) Path() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if isTCPTransport(e.transport()) {
		return ""
	}
	return e.path
}

// Addr returns the address currently being served, as the listener reports it, or "" when
// stopped. It differs from the configured address only when the port was left to the
// kernel, and it is how a caller of RebindTCP learns which port that turned out to be.
func (e *endpoint) Addr() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.addr
}

// target returns the target the endpoint is serving, as the config spelled it: a socket
// path, or the configured host:port even when the port was left to the kernel. Two
// reloads of one config compare equal through it, which the actual address does not when
// the port was 0, and it is what reportRebind decides "moved" from.
func (e *endpoint) target() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.path
}

// bound reports whether the endpoint is serving, on any transport. Path alone is not
// that answer: it is empty for an endpoint served over TCP, which is still up.
func (e *endpoint) bound() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.closer != nil
}

// rebindLocked brings the endpoint into the state the config asks for: serving at target
// with acc, over t. It works from any starting state, and a failure leaves the endpoint as
// it was. serve starts serving on the new listener and returns what to close to stop. The
// caller must hold e.mu.
//
// target is a socket path for socketTransport and a host:port address for tcpTransport;
// the transport is what gives it meaning, which is why a reload that changes transport is
// always a move even when the two read alike.
func (e *endpoint) rebindLocked(ctx context.Context, t transport, target string, acc Access, serve func(net.Listener) io.Closer) error {
	if t == nil {
		t = socketTransport{}
	}

	// A reload can move an endpoint between transports, a socket and a TCP address, so
	// the live bind's transport is what decides whether the new target names the same
	// endpoint as the old: two spellings of one address, or of one socket path, are a
	// change to apply in place, while a socket path and an address are never the same
	// endpoint even when they read alike.
	live := e.transport()
	if e.closer != nil && live.sameTarget(e.path, target) && sameTransport(live, t) {
		if id, ok := t.identify(target); ok && id == e.id {
			if !t.accessChanged(e.access, acc) {
				return nil
			}
			err := t.applyAccess(target, acc)
			if err == nil {
				e.access = acc
				e.l.Info("Changed the "+e.name+"'s socket access", "path", target, "access", acc.String())
				return nil
			}
			if errors.Is(err, errAccessFixed) {
				if e.access.narrowedBy(acc) {
					// Keeping the endpoint would keep admitting who the config no longer
					// names, so it is stopped instead. A restart serves it as configured; so
					// does a reload once every client has let go of the name.
					e.l.Error("Stopped the "+e.name+", its access cannot be narrowed while it is served; restart nebula to serve it as configured",
						"path", target, "served", e.access.String(), "configured", acc.String())
					e.stopLocked()
					return nil
				}
				e.l.Warn("The "+e.name+"'s access cannot be widened while it is served; restart nebula to apply it",
					"path", target, "serving", e.access.String(), "configured", acc.String())
				return nil
			}
			return fmt.Errorf("could not change the access of %s: %w", target, err)
		} else {
			// The node at path is not the one this endpoint bound: something outside nebula
			// removed or replaced it, logind clearing /run/user/<uid> on logout, say. The old
			// listener is unreachable, so the endpoint is stopped before the path is bound
			// again below. Stopping first, rather than after a successful bind as a move
			// does, means a bind that fails leaves the endpoint reported as down, which it
			// is, rather than as serving a path nothing can reach.
			e.l.Warn("The "+e.name+"'s socket is no longer at its path, binding it again", "path", target)
			e.stopLocked()
		}
	}

	ln, err := t.listen(target, acc)
	if err != nil {
		return err
	}
	id, _ := t.identify(target)

	// A reload that arrives during shutdown must not bring the endpoint back. Stop is
	// not terminal (a Rebind after Stop is how an endpoint whose first bind failed
	// comes up).
	if err := ctx.Err(); err != nil {
		release(t, ln, target, id)
		return fmt.Errorf("not starting the %s, nebula is shutting down: %w", e.name, err)
	}

	old, oldT, oldPath, oldID := e.closer, e.t, e.path, e.id
	e.closer = serve(ln)
	e.t = t
	e.path = target
	if isTCPTransport(t) {
		e.addr = ln.Addr().String()
	} else {
		e.addr = ""
	}
	e.access = acc
	e.id = id
	e.stopOnCancelLocked(ctx)

	// Stop serving the old endpoint, which the checks above leave only on another target.
	if old != nil {
		release(oldT, old, oldPath, oldID)
	}

	return nil
}

// sameTransport reports whether two transports are the same kind, which the endpoint
// lifecycle needs before it can say a new target names the endpoint it is serving: the
// comparison of targets is only meaningful within one transport.
func sameTransport(a, b transport) bool {
	return isTCPTransport(a) == isTCPTransport(b)
}

// transport returns the endpoint's transport, defaulting to the platform's socket so
// that an endpoint built without one is a socket endpoint.
func (e *endpoint) transport() transport {
	if e.t != nil {
		return e.t
	}
	return socketTransport{}
}

// stopOnCancelLocked arranges for the endpoint to stop when ctx is cancelled. It is
// armed once per run of the endpoint, from a successful bind until Stop, so a Rebind on
// a running endpoint does not arm it twice, and a later run is tied to the ctx that
// started it rather than an earlier one. Callers hold e.mu.
func (e *endpoint) stopOnCancelLocked(ctx context.Context) {
	if e.cancelStop != nil {
		return
	}
	e.cancelStop = context.AfterFunc(ctx, e.Stop)
}

// Stop closes the endpoint and removes its socket. Work in flight is the closer's
// business: a listener leaves the connections it already accepted to finish, a server
// cuts them off.
//
// The whole of it runs under e.mu, closer and socket included, so a Rebind cannot land
// between the state change and the close and find a path that is still bound by the
// socket it is replacing.
func (e *endpoint) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopLocked()
}

// stopLocked is Stop for a caller that holds e.mu. It leaves the endpoint as a fresh
// one, so the next bind starts a new run.
func (e *endpoint) stopLocked() {
	if e.closer == nil {
		return
	}
	release(e.transport(), e.closer, e.path, e.id)
	e.closer, e.path, e.addr, e.access, e.id = nil, "", "", Access{}, socketID{}
	if e.cancelStop != nil {
		e.cancelStop()
		e.cancelStop = nil
	}
}

// release gives up an endpoint's closer and, on a transport that has one, the node at its
// path. The node goes first, while the socket is still open: for as long as it is, the
// node is this endpoint's, since a starting daemon's stale check refuses to remove a
// socket that answers. The other order opens a window between the close and the unlink in
// which a new daemon can find the node stale, clear it and bind its own at the same path,
// which the unlink then takes from under it, leaving that daemon serving a socket nothing
// can reach. listen turns off the listener's own unlink on close so this is the only
// unlink. id is the node listen created, and the only node removeSocket will remove: one
// that replaced it, another daemon's socket bound after ours was taken from under us, is
// left alone. A TCP address has no node: remove is a no-op there, and closing the listener
// is the whole of giving it up.
func release(t transport, c io.Closer, path string, id socketID) {
	t.remove(path, id)
	_ = c.Close()
}
