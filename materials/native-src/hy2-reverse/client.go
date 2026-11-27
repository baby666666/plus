package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

type clientSession struct {
	c        *Config
	stat     *tracker
	opt      timings
	id       string
	conn     net.Conn
	writer   controlWriter
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	jobs     map[string]*clientJob
	mappings map[string]Mapping
	wg       sync.WaitGroup
}
type clientJob struct {
	id      string
	mapping Mapping
	session *clientSession
	mu      sync.Mutex
	target  net.Conn
	work    net.Conn
}

func runClient(ctx context.Context, c *Config, stat *tracker, opt timings) error {
	backoff := opt.retry
	for {
		if ctx.Err() != nil {
			return nil
		}
		stat.setState("connecting", false, "")
		connected, err := connectClient(ctx, c, stat, opt)
		if ctx.Err() != nil {
			return nil
		}
		if connected {
			backoff = opt.retry
		}
		stat.setState("error", false, errorCode(err, "control_lost"))
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		if backoff < opt.maxRetry {
			backoff *= 2
			if backoff > opt.maxRetry {
				backoff = opt.maxRetry
			}
		}
	}
}
func connectClient(ctx context.Context, c *Config, stat *tracker, opt timings) (bool, error) {
	conn, err := dialSOCKS(ctx, c.Socks, c.Control)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(opt.handshake))
	if writeMessage(conn, message{Kind: "control", Token: c.Token, Digest: c.digest}) != nil {
		return false, codedError("control_unreachable")
	}
	ack, err := readMessage(conn)
	if err != nil {
		return false, codedError("control_unreachable")
	}
	if ack.Kind != "ready" || !ack.OK || !validHex(ack.Session, 16) {
		return false, codedError(safeCode(ack.Error))
	}
	_ = conn.SetDeadline(time.Time{})
	child, cancel := context.WithCancel(ctx)
	se := &clientSession{c: c, stat: stat, opt: opt, id: ack.Session, conn: conn, writer: controlWriter{conn: conn}, ctx: child, cancel: cancel, jobs: map[string]*clientJob{}, mappings: map[string]Mapping{}}
	for _, m := range c.Mappings {
		se.mappings[m.ID] = m
		stat.listen(m.ID, true)
	}
	stat.setState("online", true, "")
	stat.heartbeat()
	defer func() { se.close(); se.wg.Wait() }()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(opt.controlTimeout))
		m, err := readMessage(conn)
		if err != nil {
			return true, codedError("control_lost")
		}
		if m.Session != se.id {
			return true, codedError("protocol_error")
		}
		switch m.Kind {
		case "ping":
			if se.writer.send(message{Kind: "pong", Session: se.id}) != nil {
				return true, codedError("control_lost")
			}
			stat.heartbeat()
		case "open":
			mapping, ok := se.mappings[m.Mapping]
			if !ok || !validHex(m.Job, 16) {
				return true, codedError("protocol_error")
			}
			se.mu.Lock()
			if _, exists := se.jobs[m.Job]; exists {
				se.mu.Unlock()
				return true, codedError("protocol_error")
			}
			if len(se.jobs) >= maxSessions {
				se.mu.Unlock()
				stat.mapError(mapping.ID, "session_limit")
				continue
			}
			job := &clientJob{id: m.Job, mapping: mapping, session: se}
			se.jobs[m.Job] = job
			se.wg.Add(1)
			se.mu.Unlock()
			stat.active(mapping.ID, 1)
			go func() { defer se.wg.Done(); defer se.finishJob(job); job.forward() }()
		default:
			return true, codedError("protocol_error")
		}
	}
}
func (se *clientSession) close() {
	se.cancel()
	se.conn.Close()
	se.mu.Lock()
	jobs := make([]*clientJob, 0, len(se.jobs))
	for _, j := range se.jobs {
		jobs = append(jobs, j)
	}
	se.mu.Unlock()
	for _, j := range jobs {
		j.close()
	}
}
func (j *clientJob) close() {
	j.mu.Lock()
	target, work := j.target, j.work
	j.mu.Unlock()
	if target != nil {
		target.Close()
	}
	if work != nil {
		work.Close()
	}
}
func (j *clientJob) setConn(conn net.Conn, target bool) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.session.ctx.Err() != nil {
		conn.Close()
		return false
	}
	if target {
		j.target = conn
	} else {
		j.work = conn
	}
	return true
}
func (se *clientSession) finishJob(j *clientJob) {
	j.close()
	se.mu.Lock()
	delete(se.jobs, j.id)
	se.mu.Unlock()
	se.stat.active(j.mapping.ID, -1)
}
func (j *clientJob) forward() {
	se := j.session
	target, targetErr := dialTarget(se.ctx, j.mapping.Protocol, j.mapping.Target, se.c.TargetMark)
	if targetErr == nil && !j.setConn(target, true) {
		return
	}
	work, err := dialSOCKS(se.ctx, se.c.Socks, se.c.Control)
	if err != nil {
		if se.ctx.Err() == nil {
			se.stat.mapError(j.mapping.ID, "work_unreachable")
		}
		return
	}
	if !j.setConn(work, false) {
		return
	}
	_ = work.SetDeadline(time.Now().Add(se.opt.handshake))
	header := message{Kind: "work", Token: se.c.Token, Digest: se.c.digest, Session: se.id, Job: j.id, Mapping: j.mapping.ID, OK: targetErr == nil}
	if targetErr != nil {
		header.Error = errorCode(targetErr, "target_unreachable")
		se.stat.mapError(j.mapping.ID, header.Error)
	}
	if writeMessage(work, header) != nil {
		if se.ctx.Err() == nil {
			se.stat.mapError(j.mapping.ID, "work_unreachable")
		}
		return
	}
	if targetErr != nil {
		return
	}
	ack, err := readMessage(work)
	if err != nil || ack.Kind != "attached" || !ack.OK || ack.Job != j.id || ack.Session != se.id {
		if se.ctx.Err() == nil {
			se.stat.mapError(j.mapping.ID, "work_rejected")
		}
		return
	}
	_ = work.SetDeadline(time.Time{})
	if j.mapping.Protocol == "tcp" {
		se.stat.success(j.mapping.ID)
		err = tcpWorkPair(se.ctx, target, work, func(n int) { se.stat.bytes(j.mapping.ID, 0, n) }, func(n int) { se.stat.bytes(j.mapping.ID, n, 0) })
		if err != nil && se.ctx.Err() == nil {
			se.stat.mapError(j.mapping.ID, "transfer_failed")
		}
	} else {
		err = udpClientPair(se.ctx, work, target, se.stat, j.mapping.ID)
		if err != nil && !errors.Is(err, net.ErrClosed) && se.ctx.Err() == nil {
			// EOF is the server expiring a quiet UDP association, not evidence
			// that the target is unreachable. Re-created on the next datagram.
			if err.Error() != "EOF" {
				se.stat.mapError(j.mapping.ID, "udp_error")
			}
		}
	}
}
