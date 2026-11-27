package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var fast = timings{50 * time.Millisecond, time.Second, 2 * time.Second, 3 * time.Second, 500 * time.Millisecond, 20 * time.Millisecond, 100 * time.Millisecond}

func freeAddress(t *testing.T, protocol string) string {
	t.Helper()
	if protocol == "udp" {
		l, e := net.ListenPacket("udp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		s := l.LocalAddr().String()
		l.Close()
		return s
	}
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	s := l.Addr().String()
	l.Close()
	return s
}
func waitFor(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out: " + what)
}

type running struct {
	cancel context.CancelFunc
	done   chan error
	stat   *tracker
	once   sync.Once
}

func launch(t *testing.T, c *Config) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{cancel: cancel, done: make(chan error, 1), stat: newTracker(c)}
	go func() {
		var err error
		if c.Mode == "server" {
			err = runServer(ctx, c, r.stat, fast)
		} else {
			err = runClient(ctx, c, r.stat, fast)
		}
		r.stat.finish()
		r.done <- err
	}()
	t.Cleanup(func() { r.stop(t) })
	return r
}
func (r *running) stop(t *testing.T) {
	t.Helper()
	r.once.Do(func() {
		r.cancel()
		select {
		case err := <-r.done:
			if err != nil {
				t.Errorf("daemon stop: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("daemon failed to stop")
		}
	})
}

type socksFixture struct {
	address      string
	mu           sync.Mutex
	destinations []string
	stop         func()
}

func startSOCKS(t *testing.T, closeBothOnEOF ...bool) *socksFixture {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &socksFixture{address: l.Addr().String()}
	var wg sync.WaitGroup
	f.stop = func() { cancel(); l.Close(); wg.Wait() }
	t.Cleanup(f.stop)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				var greeting [3]byte
				if _, err = io.ReadFull(c, greeting[:]); err != nil || greeting != [3]byte{5, 1, 0} {
					return
				}
				if writeAll(c, []byte{5, 0}) != nil {
					return
				}
				var request [10]byte
				if _, err = io.ReadFull(c, request[:]); err != nil || request[0] != 5 || request[1] != 1 || request[3] != 1 {
					return
				}
				dest := net.JoinHostPort(net.IP(request[4:8]).String(), strconv.Itoa(int(binary.BigEndian.Uint16(request[8:10]))))
				f.mu.Lock()
				f.destinations = append(f.destinations, dest)
				f.mu.Unlock()
				remote, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", dest)
				if err != nil {
					_ = writeAll(c, []byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				if writeAll(c, []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}) != nil {
					remote.Close()
					return
				}
				_ = c.SetDeadline(time.Time{})
				if len(closeBothOnEOF) > 0 && closeBothOnEOF[0] {
					// Some real SOCKS/HY2 relays close both directions on
					// either transport EOF. Logical FIN must stay in-band.
					stop := context.AfterFunc(ctx, func() { c.Close(); remote.Close() })
					done := make(chan struct{}, 2)
					copyThenClose := func(dst, src net.Conn) {
						_, _ = io.Copy(dst, src)
						c.Close()
						remote.Close()
						done <- struct{}{}
					}
					go copyThenClose(c, remote)
					go copyThenClose(remote, c)
					<-done
					<-done
					stop()
				} else {
					_ = copyPair(ctx, c, remote, func(int) {}, func(int) {})
				}
			}(conn)
		}
	}()
	return f
}
func (s *socksFixture) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.destinations) }

func tcpEcho(t *testing.T, halfClose bool) string {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() { cancel(); l.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				if halfClose {
					b, e := io.ReadAll(io.LimitReader(c, 2<<20))
					if e == nil {
						_ = writeAll(c, append([]byte("RESPONSE:"), b...))
						closeWrite(c)
					}
				} else {
					_, _ = io.Copy(c, c)
				}
			}(c)
		}
	}()
	return l.Addr().String()
}
func udpEcho(t *testing.T) string {
	t.Helper()
	l, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		for {
			n, a, e := l.ReadFromUDP(b)
			if e != nil {
				return
			}
			_, _ = l.WriteToUDP(b[:n], a)
		}
	}()
	t.Cleanup(func() { l.Close(); <-done })
	return l.LocalAddr().String()
}
func connectPair(t *testing.T, mappings []Mapping, closeBothOnEOF ...bool) (*running, *running, *socksFixture, *Config, *Config) {
	t.Helper()
	proxy := startSOCKS(t, closeBothOnEOF...)
	control := freeAddress(t, "tcp")
	sc := testConfig(t, "server", control, "", mappings)
	cc := testConfig(t, "client", control, proxy.address, mappings)
	s := launch(t, sc)
	c := launch(t, cc)
	waitFor(t, "authenticated pair", func() bool { return s.stat.snapshot().Connected && c.stat.snapshot().Connected })
	return s, c, proxy, sc, cc
}
func tcpRoundTrip(t *testing.T, address string, payload []byte) {
	t.Helper()
	c, e := net.DialTimeout("tcp4", address, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if e = writeAll(c, payload); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, len(payload))
	if _, e = io.ReadFull(c, got); e != nil || !bytes.Equal(got, payload) {
		t.Fatalf("TCP echo: %v, %q", e, got)
	}
}

func TestTCPHalfCloseAndAllWorkUsesSOCKS(t *testing.T) {
	testTCPHalfClose(t, false)
}

func TestTCPHalfCloseAcrossCarrierThatClosesBothDirectionsOnEOF(t *testing.T) {
	testTCPHalfClose(t, true)
}

func testTCPHalfClose(t *testing.T, closeBothOnEOF bool) {
	t.Helper()
	target := tcpEcho(t, true)
	listen := freeAddress(t, "tcp")
	s, c, proxy, _, _ := connectPair(t, []Mapping{{ID: "1", Protocol: "tcp", Listen: listen, Target: target, Allow: []string{"127.0.0.0/8"}}}, closeBothOnEOF)
	conn, err := net.Dial("tcp4", listen)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("half-close-data/"), 65536)
	if err = writeAll(conn, payload); err != nil {
		t.Fatal(err)
	}
	closeWrite(conn)
	result, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, append([]byte("RESPONSE:"), payload...)) {
		t.Fatalf("half-closed stream truncated: %d", len(result))
	}
	waitFor(t, "work accounting", func() bool {
		x := s.stat.snapshot().Mappings[0]
		return x.Active == 0 && x.RXBytes == uint64(len(payload)) && x.TXBytes == uint64(len(result))
	})
	if proxy.count() < 2 {
		t.Fatal("work connection bypassed SOCKS")
	}
	if c.stat.snapshot().Mappings[0].LastSuccess == 0 {
		t.Fatal("target success not recorded")
	}
}

func TestUDPDatagramsEmptyLargeAndIdleCleanup(t *testing.T) {
	listen := freeAddress(t, "udp")
	s, _, proxy, _, _ := connectPair(t, []Mapping{{ID: "1", Protocol: "udp", Listen: listen, Target: udpEcho(t), Allow: []string{"127.0.0.1/32"}}})
	c, err := net.Dial("udp4", listen)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, payload := range [][]byte{[]byte("udp"), {}, bytes.Repeat([]byte{0x5a}, maxDatagram)} {
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = c.Write(payload); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 65535)
		n, err := c.Read(buf)
		if err != nil || !bytes.Equal(payload, buf[:n]) {
			t.Fatalf("UDP length=%d: n=%d err=%v", len(payload), n, err)
		}
	}
	waitFor(t, "UDP association expiry", func() bool { return s.stat.snapshot().Mappings[0].Active == 0 })
	if proxy.count() < 2 {
		t.Fatal("UDP work did not use SOCKS")
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte("recreate"))
	buf := make([]byte, 20)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "recreate" {
		t.Fatalf("UDP recreate: %v", err)
	}
}

func TestSOCKSFailureNeverDialsControlDirectly(t *testing.T) {
	control := freeAddress(t, "tcp")
	listen := freeAddress(t, "tcp")
	m := []Mapping{{ID: "1", Protocol: "tcp", Listen: listen, Target: tcpEcho(t, false), Allow: []string{"0.0.0.0/0"}}}
	s := launch(t, testConfig(t, "server", control, "", m))
	c := launch(t, testConfig(t, "client", control, freeAddress(t, "tcp"), m))
	waitFor(t, "SOCKS failure", func() bool { return c.stat.snapshot().Error == "socks_unreachable" })
	if s.stat.snapshot().Connected {
		t.Fatal("client fell back to direct control connection")
	}
	if conn, e := net.DialTimeout("tcp4", listen, 100*time.Millisecond); e == nil {
		conn.Close()
		t.Fatal("unauthenticated mapping was exposed")
	}
}

func rawControl(t *testing.T, c *Config, token, digest string) (net.Conn, message) {
	t.Helper()
	var conn net.Conn
	var err error
	waitFor(t, "control listener", func() bool { conn, err = net.DialTimeout("tcp4", c.Control, 100*time.Millisecond); return err == nil })
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err = writeMessage(conn, message{Kind: "control", Token: token, Digest: digest}); err != nil {
		t.Fatal(err)
	}
	ack, err := readMessage(conn)
	if err != nil {
		t.Fatal(err)
	}
	return conn, ack
}
func TestWrongTokenAndMappingDigestAreRejected(t *testing.T) {
	control := freeAddress(t, "tcp")
	listen := freeAddress(t, "tcp")
	sc := testConfig(t, "server", control, "", []Mapping{{ID: "1", Protocol: "tcp", Listen: listen, Target: tcpEcho(t, false), Allow: []string{"0.0.0.0/0"}}})
	s := launch(t, sc)
	for _, sample := range []struct{ token, digest, code string }{{strings.Repeat("b2", 32), sc.digest, "authentication_failed"}, {sc.Token, strings.Repeat("c3", 32), "configuration_mismatch"}} {
		conn, ack := rawControl(t, sc, sample.token, sample.digest)
		conn.Close()
		if ack.Error != sample.code {
			t.Fatalf("got %q want %q", ack.Error, sample.code)
		}
		if s.stat.snapshot().Connected {
			t.Fatal("failed authentication reported online")
		}
		if x, e := net.DialTimeout("tcp4", listen, 100*time.Millisecond); e == nil {
			x.Close()
			t.Fatal("failed authentication opened listener")
		}
	}
}

func TestSourceACLAndTargetFailureStatus(t *testing.T) {
	listen1, listen2 := freeAddress(t, "tcp"), freeAddress(t, "tcp")
	s, _, _, _, _ := connectPair(t, []Mapping{{ID: "1", Protocol: "tcp", Listen: listen1, Target: tcpEcho(t, false), Allow: []string{"192.0.2.0/24"}}, {ID: "2", Protocol: "tcp", Listen: listen2, Target: freeAddress(t, "tcp"), Allow: []string{"0.0.0.0/0"}}})
	for _, addr := range []string{listen1, listen2} {
		conn, e := net.Dial("tcp4", addr)
		if e != nil {
			t.Fatal(e)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = conn.Write([]byte("test"))
		b := make([]byte, 1)
		if n, _ := conn.Read(b); n != 0 {
			t.Fatal("unexpected target response")
		}
		conn.Close()
	}
	waitFor(t, "target and ACL failures", func() bool {
		m := s.stat.snapshot().Mappings
		return m[0].LastError == "source_denied" && m[1].LastError == "target_unreachable" && m[0].Active == 0 && m[1].Active == 0
	})
	if !s.stat.snapshot().Connected {
		t.Fatal("target failure incorrectly disconnected healthy tunnel")
	}
}

func TestMappingBindConflictRollsBackEveryListener(t *testing.T) {
	busy, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer busy.Close()
	free := freeAddress(t, "tcp")
	sc := testConfig(t, "server", freeAddress(t, "tcp"), "", []Mapping{{ID: "1", Protocol: "tcp", Listen: free, Target: freeAddress(t, "tcp"), Allow: []string{"0.0.0.0/0"}}, {ID: "2", Protocol: "tcp", Listen: busy.Addr().String(), Target: freeAddress(t, "tcp"), Allow: []string{"0.0.0.0/0"}}})
	s := launch(t, sc)
	conn, ack := rawControl(t, sc, sc.Token, sc.digest)
	conn.Close()
	if ack.Error != "mapping_listen_failed" {
		t.Fatalf("bind error: %+v", ack)
	}
	waitFor(t, "rolled back listener", func() bool {
		l, err := net.Listen("tcp4", free)
		if err == nil {
			l.Close()
			return true
		}
		return false
	})
	if s.stat.snapshot().Connected {
		t.Fatal("partial bind reported online")
	}
}

func TestDisconnectClosesMappingsAndClientReconnects(t *testing.T) {
	listen := freeAddress(t, "tcp")
	s, c, _, sc, _ := connectPair(t, []Mapping{{ID: "1", Protocol: "tcp", Listen: listen, Target: tcpEcho(t, false), Allow: []string{"0.0.0.0/0"}}})
	tcpRoundTrip(t, listen, []byte("before"))
	s.stop(t)
	waitFor(t, "client observes disconnect", func() bool { return !c.stat.snapshot().Connected })
	if conn, e := net.DialTimeout("tcp4", listen, 100*time.Millisecond); e == nil {
		conn.Close()
		t.Fatal("listener survived server stop")
	}
	restarted := launch(t, sc)
	waitFor(t, "automatic reconnect", func() bool { return restarted.stat.snapshot().Connected && c.stat.snapshot().Connected })
	tcpRoundTrip(t, listen, []byte("after"))
	c.stop(t)
	waitFor(t, "server closes offline mappings", func() bool {
		return !restarted.stat.snapshot().Connected && !restarted.stat.snapshot().Mappings[0].Listening
	})
}

func TestStatusFileIsAtomicPrivateAndContainsNoCredential(t *testing.T) {
	listen := freeAddress(t, "tcp")
	s, _, _, sc, _ := connectPair(t, []Mapping{{ID: "1", Protocol: "tcp", Listen: listen, Target: tcpEcho(t, false), Allow: []string{"0.0.0.0/0"}}})
	tcpRoundTrip(t, listen, []byte("status"))
	waitFor(t, "status file", func() bool {
		b, e := os.ReadFile(sc.StatusFile)
		if e != nil {
			return false
		}
		var status Status
		if json.Unmarshal(b, &status) != nil {
			return false
		}
		return status.Connected && status.ConfigSHA256 == sc.fileHash && status.Mappings[0].LastSuccess > 0
	})
	b, _ := os.ReadFile(sc.StatusFile)
	if bytes.Contains(b, []byte(sc.Token)) {
		t.Fatal("token leaked in status")
	}
	info, e := os.Stat(sc.StatusFile)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("status permissions: %v", e)
	}
	s.stop(t)
	b, _ = os.ReadFile(sc.StatusFile)
	var last Status
	_ = json.Unmarshal(b, &last)
	if last.Connected || last.State != "stopped" {
		t.Fatal("shutdown left stale online state")
	}
}
