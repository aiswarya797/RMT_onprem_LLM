//go:build !darwin

package lifecycle

import "net"

func sameUserPeer(net.Conn) bool { return false }
