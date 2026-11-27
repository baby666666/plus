package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

func dialSOCKS(ctx context.Context, proxy, destination string) (net.Conn, error) {
	d := net.Dialer{Timeout: 8 * time.Second, KeepAlive: 20 * time.Second}
	c, err := d.DialContext(ctx, "tcp4", proxy)
	if err != nil {
		return nil, codedError("socks_unreachable")
	}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	deadline := time.Now().Add(8 * time.Second)
	if x, yes := ctx.Deadline(); yes && x.Before(deadline) {
		deadline = x
	}
	_ = c.SetDeadline(deadline)
	if writeAll(c, []byte{5, 1, 0}) != nil {
		return nil, codedError("socks_unreachable")
	}
	var method [2]byte
	if _, err = io.ReadFull(c, method[:]); err != nil || method != [2]byte{5, 0} {
		return nil, codedError("socks_rejected")
	}
	ip, port, err := endpoint(destination, false)
	if err != nil {
		return nil, codedError("protocol_error")
	}
	request := []byte{5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)}
	if writeAll(c, request) != nil {
		return nil, codedError("control_unreachable")
	}
	var reply [4]byte
	if _, err = io.ReadFull(c, reply[:]); err != nil || reply[0] != 5 || reply[1] != 0 || reply[2] != 0 {
		return nil, codedError("control_unreachable")
	}
	n := 0
	switch reply[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var b [1]byte
		if _, err = io.ReadFull(c, b[:]); err != nil {
			return nil, codedError("socks_rejected")
		}
		n = int(b[0])
	default:
		return nil, codedError("socks_rejected")
	}
	var tail [258]byte
	if _, err = io.ReadFull(c, tail[:n+2]); err != nil {
		return nil, codedError("socks_rejected")
	}
	_ = c.SetDeadline(time.Time{})
	if ctx.Err() != nil {
		return nil, codedError("control_unreachable")
	}
	ok = true
	return c, nil
}

type countingWriter struct {
	conn  net.Conn
	count func(int)
}

func (w countingWriter) Write(b []byte) (int, error) {
	n, e := w.conn.Write(b)
	if n > 0 {
		w.count(n)
	}
	return n, e
}
func closeWrite(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
}
func copyPair(ctx context.Context, a, b net.Conn, fromA, fromB func(int)) error {
	stop := context.AfterFunc(ctx, func() { a.Close(); b.Close() })
	defer stop()
	defer a.Close()
	defer b.Close()
	errs := make(chan error, 2)
	copyOne := func(dst, src net.Conn, count func(int)) {
		_, err := io.CopyBuffer(countingWriter{dst, count}, src, make([]byte, 32*1024))
		closeWrite(dst)
		if err != nil {
			a.Close()
			b.Close()
		}
		errs <- err
	}
	go copyOne(b, a, fromA)
	go copyOne(a, b, fromB)
	e1, e2 := <-errs, <-errs
	if e1 != nil {
		return e1
	}
	return e2
}

const (
	tcpFrameMax = 32 * 1024
	tcpFrameFIN = 0
	tcpFrameACK = 65535
)

// tcpWorkPair preserves logical TCP half-closes across proxy carriers that
// close both directions when either underlying stream reaches EOF. Only the
// local TCP socket is half-closed; the work stream carries explicit FIN/ACK.
// An ACK confirms all preceding payload was written to the receiving socket.
func tcpWorkPair(ctx context.Context, local, work net.Conn, fromLocal, fromWork func(int)) error {
	stop := context.AfterFunc(ctx, func() { local.Close(); work.Close() })
	defer stop()
	defer local.Close()
	defer work.Close()
	var writer sync.Mutex
	var sentFIN atomic.Bool
	send := func(kind int, payload []byte) error {
		writer.Lock()
		defer writer.Unlock()
		if kind == tcpFrameFIN {
			sentFIN.Store(true)
		}
		var head [2]byte
		binary.BigEndian.PutUint16(head[:], uint16(kind))
		if err := writeAll(work, head[:]); err != nil {
			return err
		}
		return writeAll(countingWriter{work, fromLocal}, payload)
	}
	errs := make(chan error, 2)
	finish := func(err error) {
		// Report the originating error before closing the other direction;
		// otherwise its consequent closed-socket error can hide the cause.
		errs <- err
		if err != nil {
			local.Close()
			work.Close()
		}
	}
	go func() {
		buf := make([]byte, tcpFrameMax)
		for {
			n, err := local.Read(buf)
			if n > 0 {
				if sendErr := send(n, buf[:n]); sendErr != nil {
					finish(sendErr)
					return
				}
			}
			if err == io.EOF {
				finish(send(tcpFrameFIN, nil))
				return
			}
			if err != nil {
				finish(err)
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, tcpFrameMax)
		var head [2]byte
		remoteFIN, acknowledged := false, false
		for !remoteFIN || !acknowledged {
			if _, err := io.ReadFull(work, head[:]); err != nil {
				finish(err)
				return
			}
			n := int(binary.BigEndian.Uint16(head[:]))
			switch n {
			case tcpFrameFIN:
				if remoteFIN {
					finish(codedError("protocol_error"))
					return
				}
				remoteFIN = true
				closeWrite(local)
				if err := send(tcpFrameACK, nil); err != nil {
					finish(err)
					return
				}
			case tcpFrameACK:
				if acknowledged || !sentFIN.Load() {
					finish(codedError("protocol_error"))
					return
				}
				acknowledged = true
			default:
				if remoteFIN || n > len(buf) {
					finish(codedError("protocol_error"))
					return
				}
				if _, err := io.ReadFull(work, buf[:n]); err != nil {
					finish(err)
					return
				}
				if err := writeAll(countingWriter{local, fromWork}, buf[:n]); err != nil {
					finish(err)
					return
				}
			}
		}
		finish(nil)
	}()
	e1, e2 := <-errs, <-errs
	if e1 != nil {
		return e1
	}
	return e2
}

func udpClientPair(ctx context.Context, work net.Conn, target net.Conn, stat *tracker, id string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { work.Close(); target.Close() })
	defer stop()
	defer work.Close()
	defer target.Close()
	errs := make(chan error, 2)
	go func() {
		for {
			b, err := readDatagram(work)
			if err != nil {
				errs <- err
				return
			}
			_ = target.SetWriteDeadline(time.Now().Add(10 * time.Second))
			n, err := target.Write(b)
			if n > 0 {
				stat.bytes(id, n, 0)
			}
			if err != nil {
				errs <- err
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := target.Read(buf)
			if err != nil {
				errs <- err
				return
			}
			if n > maxDatagram {
				continue
			}
			_ = work.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err = writeDatagram(work, buf[:n]); err != nil {
				errs <- err
				return
			}
			stat.bytes(id, 0, n)
			stat.success(id)
		}
	}()
	err := <-errs
	cancel()
	work.Close()
	target.Close()
	<-errs
	return err
}
