package main

import (
	"context"
	"net"
	"syscall"
	"time"
)

func dialTarget(ctx context.Context, protocol, address string, mark uint32) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 20 * time.Second}
	if mark != 0 {
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var inner error
			err := c.Control(func(fd uintptr) {
				inner = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
			})
			if err != nil {
				return err
			}
			if inner != nil {
				return codedError("target_mark_failed")
			}
			return nil
		}
	}
	c, err := d.DialContext(ctx, protocol+"4", address)
	if err != nil {
		if n, ok := err.(net.Error); ok && n.Timeout() {
			return nil, codedError("target_timeout")
		}
		return nil, codedError(errorCode(err, "target_unreachable"))
	}
	return c, nil
}
