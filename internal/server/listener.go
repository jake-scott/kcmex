// Package server implements the KCM Unix-socket protocol server: it
// owns the listening socket, per-connection framing, and translates
// KCM opcodes into calls on internal/krb5c. It contains no Kerberos
// protocol logic itself.
package server

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// Listen creates (or re-creates) a Unix domain socket at path for the
// KCM protocol. Since kcmex serves a single user, the socket is created
// with 0600 permissions and any stale socket file left over from a
// previous run is removed first.
func Listen(path string) (*net.UnixListener, error) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("removing stale socket %q: %w", path, err)
	}
	addr, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		return nil, err
	}
	l, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, fmt.Errorf("setting permissions on %q: %w", path, err)
	}
	return l, nil
}

// peerUID returns the effective UID of the process on the other end of
// a Unix domain socket connection.
func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			sockErr = err
			return
		}
		uid = cred.Uid
	})
	if err != nil {
		return 0, err
	}
	return uid, sockErr
}
