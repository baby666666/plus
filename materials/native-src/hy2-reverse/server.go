package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type timings struct {
	heartbeat, controlTimeout, handshake, workTimeout, udpIdle, retry, maxRetry time.Duration
}

var productionTimings = timings{10 * time.Second, 35 * time.Second, 8 * time.Second, 20 * time.Second, 60 * time.Second, time.Second, 15 * time.Second}

type reverseServer struct {
	c          *Config
	stat       *tracker
	ctx        context.Context
	opt        timings
	mu         sync.Mutex
	current    *serverSession
	unauth     map[net.Conn]bool
	closing    bool
	wg         sync.WaitGroup
	handshakes chan struct{}
}
type mapListener struct {
	mapping Mapping
	tcp     net.Listener
	udp     *net.UDPConn
}
type serverSession struct {
	server    *reverseServer
	id        string
	conn      net.Conn
	writer    controlWriter
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	closed    bool
	active    bool
	listeners []*mapListener
	jobs      map[string]*serverJob
	udpJobs   map[string]*serverJob
	udpCount  int
	wg        sync.WaitGroup
}
type workResult struct {
	conn net.Conn
	code string
}
type serverJob struct {
	session  *serverSession
	id       string
	mapping  Mapping
	external net.Conn
	udp      *net.UDPConn
	remote   *net.UDPAddr
	key      string
	queue    chan []byte
	last     atomic.Int64
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	claimed  bool
	work     net.Conn
	result   chan workResult
}

func runServer(ctx context.Context, c *Config, stat *tracker, opt timings) error {
	s := &reverseServer{c: c, stat: stat, ctx: ctx, opt: opt, unauth: map[net.Conn]bool{}, handshakes: make(chan struct{}, 32)}
	l, err := net.Listen("tcp4", c.Control)
	if err != nil {
		stat.setState("error", false, "mapping_listen_failed")
		return errors.New("control_listen_failed")
	}
	stat.setState("waiting", false, "")
	shutdown := func() {
		s.mu.Lock()
		s.closing = true
		current := s.current
		for conn := range s.unauth {
			conn.Close()
		}
		s.mu.Unlock()
		l.Close()
		if current != nil {
			current.close()
		}
	}
	stop := context.AfterFunc(ctx, shutdown)
	defer stop()
	defer shutdown()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			shutdown()
			s.wg.Wait()
			return errors.New("control_accept_failed")
		}
		select {
		case s.handshakes <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			<-s.handshakes
			conn.Close()
			break
		}
		s.unauth[conn] = true
		s.wg.Add(1)
		s.mu.Unlock()
		go func() { defer s.wg.Done(); s.handle(conn) }()
	}
	s.wg.Wait()
	return nil
}

func (s *reverseServer) handle(conn net.Conn) {
	transferred := false
	defer func() {
		s.mu.Lock()
		delete(s.unauth, conn)
		s.mu.Unlock()
		if !transferred {
			conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(s.opt.handshake))
	m, err := readMessage(conn)
	// A slot bounds unauthenticated readers; authenticated control readers are
	// separately limited to one per device.
	<-s.handshakes
	if err != nil {
		return
	}
	if !authenticated(m.Token, s.c.Token) {
		_ = writeMessage(conn, message{Kind: "error", Error: "authentication_failed"})
		return
	}
	if m.Digest != s.c.digest {
		_ = writeMessage(conn, message{Kind: "error", Error: "configuration_mismatch"})
		return
	}
	switch m.Kind {
	case "control":
		s.mu.Lock()
		if s.closing || s.current != nil {
			s.mu.Unlock()
			_ = writeMessage(conn, message{Kind: "error", Error: "client_already_online"})
			return
		}
		ctx, cancel := context.WithCancel(s.ctx)
		se := &serverSession{server: s, id: randomID(), conn: conn, writer: controlWriter{conn: conn}, ctx: ctx, cancel: cancel, jobs: map[string]*serverJob{}, udpJobs: map[string]*serverJob{}}
		s.current = se
		s.mu.Unlock()
		online := false
		defer func() {
			se.close()
			se.wg.Wait()
			s.mu.Lock()
			if s.current == se {
				s.current = nil
			}
			s.mu.Unlock()
			if s.ctx.Err() == nil && online {
				s.stat.setState("waiting", false, "control_lost")
			}
		}()
		if err = se.bind(); err != nil {
			s.stat.setState("error", false, "mapping_listen_failed")
			_ = writeMessage(conn, message{Kind: "error", Error: "mapping_listen_failed"})
			return
		}
		if err = writeMessage(conn, message{Kind: "ready", OK: true, Session: se.id}); err != nil {
			return
		}
		_ = conn.SetDeadline(time.Time{})
		s.mu.Lock()
		delete(s.unauth, conn)
		s.mu.Unlock()
		transferred = true
		se.mu.Lock()
		if se.closed {
			se.mu.Unlock()
			return
		}
		se.active = true
		se.mu.Unlock()
		online = true
		s.stat.setState("online", true, "")
		s.stat.heartbeat()
		se.start()
		se.readControl()
	case "work":
		s.mu.Lock()
		se := s.current
		s.mu.Unlock()
		if se == nil || m.Session != se.id || !validHex(m.Job, 16) {
			_ = writeMessage(conn, message{Kind: "error", Error: "session_unavailable"})
			return
		}
		se.mu.Lock()
		job := se.jobs[m.Job]
		active := se.active && !se.closed
		se.mu.Unlock()
		if !active || job == nil || m.Mapping != job.mapping.ID {
			_ = writeMessage(conn, message{Kind: "error", Error: "invalid_work"})
			return
		}
		job.mu.Lock()
		if job.claimed || job.ctx.Err() != nil {
			job.mu.Unlock()
			_ = writeMessage(conn, message{Kind: "error", Error: "invalid_work"})
			return
		}
		job.claimed = true
		if !m.OK {
			job.mu.Unlock()
			job.result <- workResult{code: safeCode(m.Error)}
			return
		}
		// Make the in-flight acknowledgement cancellable without keeping a
		// mutex held across network I/O. A session stop must close this socket
		// even if its peer stops reading the acknowledgement.
		job.work = conn
		job.mu.Unlock()
		if err = writeMessage(conn, message{Kind: "attached", OK: true, Session: se.id, Job: job.id}); err != nil {
			job.result <- workResult{code: "work_unreachable"}
			return
		}
		_ = conn.SetDeadline(time.Time{})
		if job.ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		delete(s.unauth, conn)
		s.mu.Unlock()
		transferred = true
		job.result <- workResult{conn: conn}
	default:
		_ = writeMessage(conn, message{Kind: "error", Error: "protocol_error"})
	}
}

func (se *serverSession) bind() error {
	for _, m := range se.server.c.Mappings {
		if se.ctx.Err() != nil {
			return se.ctx.Err()
		}
		entry := &mapListener{mapping: m}
		var err error
		if m.Protocol == "tcp" {
			entry.tcp, err = net.Listen("tcp4", m.Listen)
		} else {
			var addr *net.UDPAddr
			addr, err = net.ResolveUDPAddr("udp4", m.Listen)
			if err == nil {
				entry.udp, err = net.ListenUDP("udp4", addr)
			}
		}
		if err != nil {
			se.server.stat.mapError(m.ID, "mapping_listen_failed")
			return err
		}
		se.mu.Lock()
		if se.closed {
			se.mu.Unlock()
			if entry.tcp != nil {
				entry.tcp.Close()
			}
			if entry.udp != nil {
				entry.udp.Close()
			}
			return context.Canceled
		}
		se.listeners = append(se.listeners, entry)
		se.mu.Unlock()
	}
	return nil
}
func (se *serverSession) start() {
	se.mu.Lock()
	listeners := append([]*mapListener(nil), se.listeners...)
	se.mu.Unlock()
	for _, entry := range listeners {
		se.server.stat.listen(entry.mapping.ID, true)
		se.wg.Add(1)
		go func(e *mapListener) {
			defer se.wg.Done()
			if e.tcp != nil {
				se.acceptTCP(e)
			} else {
				se.acceptUDP(e)
			}
		}(entry)
	}
	se.wg.Add(1)
	go func() {
		defer se.wg.Done()
		tick := time.NewTicker(se.server.opt.heartbeat)
		defer tick.Stop()
		for {
			select {
			case <-se.ctx.Done():
				return
			case <-tick.C:
				if se.writer.send(message{Kind: "ping", Session: se.id}) != nil {
					se.close()
					return
				}
			}
		}
	}()
}
func (se *serverSession) readControl() {
	for {
		_ = se.conn.SetReadDeadline(time.Now().Add(se.server.opt.controlTimeout))
		m, err := readMessage(se.conn)
		if err != nil {
			return
		}
		if m.Kind != "pong" || m.Session != se.id {
			return
		}
		se.server.stat.heartbeat()
	}
}
func (se *serverSession) close() {
	se.mu.Lock()
	if se.closed {
		se.mu.Unlock()
		return
	}
	se.closed = true
	se.active = false
	listeners := append([]*mapListener(nil), se.listeners...)
	jobs := make([]*serverJob, 0, len(se.jobs))
	for _, j := range se.jobs {
		jobs = append(jobs, j)
	}
	se.mu.Unlock()
	se.cancel()
	se.conn.Close()
	for _, e := range listeners {
		if e.tcp != nil {
			e.tcp.Close()
		}
		if e.udp != nil {
			e.udp.Close()
		}
		se.server.stat.listen(e.mapping.ID, false)
	}
	for _, j := range jobs {
		j.close()
	}
}
func (j *serverJob) close() {
	j.cancel()
	j.mu.Lock()
	work := j.work
	j.mu.Unlock()
	if j.external != nil {
		j.external.Close()
	}
	if work != nil {
		work.Close()
	}
}
func (se *serverSession) reserve(m Mapping, external net.Conn, udp *net.UDPConn, remote *net.UDPAddr, key string) *serverJob {
	se.mu.Lock()
	defer se.mu.Unlock()
	if se.closed || !se.active || len(se.jobs) >= maxSessions || (udp != nil && se.udpCount >= maxUDPSessions) {
		return nil
	}
	ctx, cancel := context.WithCancel(se.ctx)
	j := &serverJob{session: se, id: randomID(), mapping: m, external: external, udp: udp, remote: remote, key: key, ctx: ctx, cancel: cancel, result: make(chan workResult, 1)}
	if udp != nil {
		j.queue = make(chan []byte, 2)
		se.udpJobs[key] = j
		se.udpCount++
	}
	j.last.Store(time.Now().UnixNano())
	se.jobs[j.id] = j
	se.server.stat.active(m.ID, 1)
	return j
}
func (se *serverSession) startJob(j *serverJob) {
	se.wg.Add(1)
	go func() {
		defer se.wg.Done()
		defer se.finishJob(j)
		if se.writer.send(message{Kind: "open", Session: se.id, Job: j.id, Mapping: j.mapping.ID}) != nil {
			se.close()
			return
		}
		timer := time.NewTimer(se.server.opt.workTimeout)
		defer timer.Stop()
		var result workResult
		select {
		case result = <-j.result:
		case <-j.ctx.Done():
			return
		case <-timer.C:
			se.server.stat.mapError(j.mapping.ID, "work_timeout")
			return
		}
		if result.code != "" {
			se.server.stat.mapError(j.mapping.ID, result.code)
			return
		}
		if j.ctx.Err() != nil {
			return
		}
		if j.mapping.Protocol == "tcp" {
			se.server.stat.success(j.mapping.ID)
			err := tcpWorkPair(j.ctx, j.external, result.conn, func(n int) { se.server.stat.bytes(j.mapping.ID, n, 0) }, func(n int) { se.server.stat.bytes(j.mapping.ID, 0, n) })
			if err != nil && j.ctx.Err() == nil {
				se.server.stat.mapError(j.mapping.ID, "transfer_failed")
			}
		} else {
			j.forwardUDP(result.conn)
		}
	}()
}
func (se *serverSession) finishJob(j *serverJob) {
	j.close()
	se.mu.Lock()
	delete(se.jobs, j.id)
	if j.udp != nil {
		if se.udpJobs[j.key] == j {
			delete(se.udpJobs, j.key)
		}
		se.udpCount--
	}
	se.mu.Unlock()
	se.server.stat.active(j.mapping.ID, -1)
}
func (se *serverSession) acceptTCP(e *mapListener) {
	for {
		conn, err := e.tcp.Accept()
		if err != nil {
			return
		}
		if !e.mapping.allowed(conn.RemoteAddr()) {
			conn.Close()
			se.server.stat.mapError(e.mapping.ID, "source_denied")
			continue
		}
		j := se.reserve(e.mapping, conn, nil, nil, "")
		if j == nil {
			conn.Close()
			se.server.stat.mapError(e.mapping.ID, "session_limit")
			continue
		}
		se.startJob(j)
	}
}
func (se *serverSession) acceptUDP(e *mapListener) {
	buf := make([]byte, 65535)
	for {
		n, remote, err := e.udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n > maxDatagram {
			continue
		}
		if !e.mapping.allowed(remote) {
			se.server.stat.mapError(e.mapping.ID, "source_denied")
			continue
		}
		key := e.mapping.ID + "/" + remote.String()
		se.mu.Lock()
		j := se.udpJobs[key]
		se.mu.Unlock()
		if j != nil && j.ctx.Err() != nil {
			continue
		}
		if j == nil {
			j = se.reserve(e.mapping, nil, e.udp, remote, key)
			if j == nil {
				se.server.stat.mapError(e.mapping.ID, "session_limit")
				continue
			}
			se.startJob(j)
		}
		packet := append([]byte(nil), buf[:n]...)
		j.last.Store(time.Now().UnixNano())
		select {
		case j.queue <- packet:
		default:
			se.server.stat.mapError(e.mapping.ID, "udp_queue_full")
		}
	}
}
func (j *serverJob) forwardUDP(work net.Conn) {
	stat := j.session.server.stat
	errs := make(chan error, 2)
	go func() {
		for {
			select {
			case <-j.ctx.Done():
				errs <- j.ctx.Err()
				return
			case b := <-j.queue:
				_ = work.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := writeDatagram(work, b); err != nil {
					errs <- err
					return
				}
				stat.bytes(j.mapping.ID, len(b), 0)
			}
		}
	}()
	go func() {
		for {
			b, err := readDatagram(work)
			if err != nil {
				errs <- err
				return
			}
			n, err := j.udp.WriteToUDP(b, j.remote)
			if err != nil {
				errs <- err
				return
			}
			stat.bytes(j.mapping.ID, 0, n)
			stat.success(j.mapping.ID)
			j.last.Store(time.Now().UnixNano())
		}
	}()
	interval := j.session.server.opt.udpIdle / 3
	if interval > 5*time.Second {
		interval = 5 * time.Second
	}
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	finished := 0
loop:
	for {
		select {
		case <-j.ctx.Done():
			break loop
		case err := <-errs:
			finished++
			if err != nil && j.ctx.Err() == nil {
				stat.mapError(j.mapping.ID, "udp_error")
			}
			break loop
		case <-tick.C:
			if time.Since(time.Unix(0, j.last.Load())) >= j.session.server.opt.udpIdle {
				break loop
			}
		}
	}
	j.close()
	for finished < 2 {
		<-errs
		finished++
	}
}
