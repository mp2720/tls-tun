package main

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func setFwmark(conn syscall.RawConn, fwmark uint32) error {
	var optErr error
	err := conn.Control(func(fd uintptr) {
		optErr = syscall.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(fwmark))
	})
	if err != nil {
		return err
	}
	return optErr
}
