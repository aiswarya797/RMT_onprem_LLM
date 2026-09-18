//go:build darwin

package lifecycle

import (
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func sameUserPeer(connection net.Conn) bool {
	conn, ok := connection.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	verified := false
	if err := raw.Control(func(fd uintptr) {
		credentials, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		verified = err == nil && credentials.Uid == uint32(os.Getuid())
	}); err != nil {
		return false
	}
	return verified
}
