package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func rawWork(t *testing.T, c *Config, header message) (net.Conn, message) {
	t.Helper()
	conn, err := net.Dial("tcp4", c.Control)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if err = writeMessage(conn, header); err != nil {
		t.Fatal(err)
	}
	ack, err := readMessage(conn)
	if err != nil {
		t.Fatal(err)
	}
	return conn, ack
}
func readOpen(t *testing.T, control net.Conn) message {
	t.Helper()
	for {
		m, err := readMessage(control)
		if err != nil {
			t.Fatal(err)
		}
		if m.Kind == "ping" {
			if err = writeMessage(control, message{Kind: "pong", Session: m.Session}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if m.Kind != "open" {
			t.Fatalf("unexpected control message %+v", m)
		}
		return m
	}
}

func TestWorkReplayWrongSessionAndStaleSessionRejected(t *testing.T) {
	listen := freeAddress(t, "tcp")
	sc := testConfig(t, "server", freeAddress(t, "tcp"), "", []Mapping{{ID: "1", Protocol: "tcp", Listen: listen, Target: freeAddress(t, "tcp"), Allow: []string{"0.0.0.0/0"}}})
	s := launch(t, sc)
	control, ready := rawControl(t, sc, sc.Token, sc.digest)
	defer control.Close()
	if !ready.OK {
		t.Fatalf("control not ready: %+v", ready)
	}
	external, err := net.Dial("tcp4", listen)
	if err != nil {
		t.Fatal(err)
	}
	defer external.Close()
	_ = external.SetDeadline(time.Now().Add(2 * time.Second))
	open := readOpen(t, control)
	header := message{Kind: "work", Token: sc.Token, Digest: sc.digest, Session: ready.Session, Job: open.Job, Mapping: "1", OK: true}
	wrong := header
	wrong.Session = randomID()
	bad, ack := rawWork(t, sc, wrong)
	bad.Close()
	if ack.Error != "session_unavailable" {
		t.Fatalf("wrong session accepted: %+v", ack)
	}
	work, attached := rawWork(t, sc, header)
	defer work.Close()
	if !attached.OK {
		t.Fatalf("work rejected: %+v", attached)
	}
	replay, ack := rawWork(t, sc, header)
	replay.Close()
	if ack.Error != "invalid_work" {
		t.Fatalf("replay accepted: %+v", ack)
	}
	if writeAll(external, []byte("request")) != nil {
		t.Fatal("external write")
	}
	buf, err := readDatagram(work) // Nonempty TCP data frames share the length encoding.
	if err != nil || string(buf) != "request" {
		t.Fatalf("request relay: %v", err)
	}
	if writeDatagram(work, []byte("reply")) != nil {
		t.Fatal("work write")
	}
	buf = make([]byte, 5)
	if _, err = io.ReadFull(external, buf); err != nil || string(buf) != "reply" {
		t.Fatalf("reply relay: %v", err)
	}
	control.Close()
	waitFor(t, "disconnected session cleans jobs", func() bool { x := s.stat.snapshot(); return !x.Connected && x.Mappings[0].Active == 0 })
	newControl, newReady := rawControl(t, sc, sc.Token, sc.digest)
	defer newControl.Close()
	if !newReady.OK || newReady.Session == ready.Session {
		t.Fatal("session identity not replaced")
	}
	stale, ack := rawWork(t, sc, header)
	stale.Close()
	if ack.Error != "session_unavailable" {
		t.Fatalf("stale work accepted: %+v", ack)
	}
}

func TestTCPFramesRejectOversizeAndPrematureAcknowledgement(t *testing.T) {
	for name, head := range map[string][]byte{
		"oversize":      {0x80, 0x01},
		"premature_ack": {0xff, 0xff},
	} {
		t.Run(name, func(t *testing.T) {
			local, application := net.Pipe()
			work, carrier := net.Pipe()
			defer application.Close()
			defer carrier.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- tcpWorkPair(ctx, local, work, func(int) {}, func(int) {}) }()
			if err := writeAll(carrier, head); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if errorCode(err, "transfer_failed") != "protocol_error" {
					t.Fatalf("invalid frame accepted: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("invalid frame stalled the session")
			}
		})
	}
}

func TestSecondClientCannotReplaceHealthySession(t *testing.T) {
	listen := freeAddress(t, "tcp")
	s, _, _, sc, _ := connectPair(t, []Mapping{{ID: "1", Protocol: "tcp", Listen: listen, Target: tcpEcho(t, false), Allow: []string{"0.0.0.0/0"}}})
	second, ack := rawControl(t, sc, sc.Token, sc.digest)
	second.Close()
	if ack.Error != "client_already_online" {
		t.Fatalf("duplicate session accepted: %+v", ack)
	}
	if !s.stat.snapshot().Connected {
		t.Fatal("duplicate login killed healthy session")
	}
	tcpRoundTrip(t, listen, []byte("still connected"))
}

func TestHeartbeatExpiryRevokesPublicListeners(t *testing.T) {
	listen := freeAddress(t, "tcp")
	sc := testConfig(t, "server", freeAddress(t, "tcp"), "", []Mapping{{ID: "1", Protocol: "tcp", Listen: listen, Target: freeAddress(t, "tcp"), Allow: []string{"0.0.0.0/0"}}})
	s := launch(t, sc)
	conn, ack := rawControl(t, sc, sc.Token, sc.digest)
	defer conn.Close()
	if !ack.OK {
		t.Fatal("not authenticated")
	}
	waitFor(t, "heartbeat timeout", func() bool {
		x := s.stat.snapshot()
		return !x.Connected && x.State == "waiting" && x.Error == "control_lost"
	})
	if c, e := net.DialTimeout("tcp4", listen, 100*time.Millisecond); e == nil {
		c.Close()
		t.Fatal("dead client's listener remains exposed")
	}
}

func TestUnauthenticatedSlowReaderDoesNotPreventShutdown(t *testing.T) {
	sc := testConfig(t, "server", freeAddress(t, "tcp"), "", []Mapping{{ID: "1", Protocol: "tcp", Listen: freeAddress(t, "tcp"), Target: freeAddress(t, "tcp"), Allow: []string{"0.0.0.0/0"}}})
	s := launch(t, sc)
	var conns []net.Conn
	for i := 0; i < 10; i++ {
		var c net.Conn
		waitFor(t, "control accept", func() bool {
			var e error
			c, e = net.DialTimeout("tcp4", sc.Control, 100*time.Millisecond)
			return e == nil
		})
		conns = append(conns, c)
	}
	s.stop(t)
	for _, c := range conns {
		c.Close()
	}
}

func TestWireFramesAreBoundedAndEmptyDatagramsSurvive(t *testing.T) {
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], maxMessage+1)
	if _, err := readMessage(bytes.NewReader(head[:])); err == nil {
		t.Fatal("oversized handshake accepted")
	}
	var buf bytes.Buffer
	if writeDatagram(&buf, nil) != nil {
		t.Fatal("empty datagram write")
	}
	b, err := readDatagram(&buf)
	if err != nil || len(b) != 0 {
		t.Fatalf("empty datagram changed: %v", err)
	}
	if err = writeDatagram(&buf, make([]byte, maxDatagram+1)); err == nil {
		t.Fatal("oversized datagram accepted")
	}
}

func TestUDPOverloadDropsPacketsWithoutUnboundedJobs(t *testing.T) {
	listen := freeAddress(t, "udp")
	sc := testConfig(t, "server", freeAddress(t, "tcp"), "", []Mapping{{ID: "1", Protocol: "udp", Listen: listen, Target: "127.0.0.1:9", Allow: []string{"0.0.0.0/0"}}})
	s := launch(t, sc)
	control, ack := rawControl(t, sc, sc.Token, sc.digest)
	defer control.Close()
	if !ack.OK {
		t.Fatal("control authentication failed")
	}
	// A valid but stalled client never attaches the requested work socket.
	// Repeated datagrams from the same source must remain a single bounded job.
	u, err := net.Dial("udp4", listen)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	for i := 0; i < 20; i++ {
		if _, err = u.Write([]byte("bounded")); err != nil {
			t.Fatal(err)
		}
	}
	open := readOpen(t, control)
	if open.Mapping != "1" {
		t.Fatal("wrong mapping requested")
	}
	waitFor(t, "bounded UDP overload", func() bool {
		m := s.stat.snapshot().Mappings[0]
		return m.Active == 1 && m.LastError == "udp_queue_full"
	})
	control.Close()
	waitFor(t, "pending UDP cleanup", func() bool { return s.stat.snapshot().Mappings[0].Active == 0 })
}
