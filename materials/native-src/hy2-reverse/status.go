package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type MappingStatus struct {
	ID          string `json:"id"`
	Listening   bool   `json:"listening"`
	Active      int    `json:"active"`
	RXBytes     uint64 `json:"rx_bytes"`
	TXBytes     uint64 `json:"tx_bytes"`
	LastError   string `json:"last_error"`
	LastSuccess int64  `json:"last_success"`
}
type Status struct {
	Version       int             `json:"version"`
	Mode          string          `json:"mode"`
	ConfigSHA256  string          `json:"config_sha256"`
	PID           int             `json:"pid"`
	State         string          `json:"state"`
	Connected     bool            `json:"connected"`
	Error         string          `json:"error"`
	LastHeartbeat int64           `json:"last_heartbeat"`
	UpdatedAt     int64           `json:"updated_at"`
	Mappings      []MappingStatus `json:"mappings"`
}
type tracker struct {
	mu     sync.Mutex
	status Status
	index  map[string]int
	path   string
	dirty  chan struct{}
	stop   chan struct{}
	done   chan struct{}
}

func newTracker(c *Config) *tracker {
	t := &tracker{path: c.StatusFile, index: map[string]int{}, dirty: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	t.status = Status{Version: 1, Mode: c.Mode, ConfigSHA256: c.fileHash, PID: os.Getpid(), State: "initializing", Mappings: make([]MappingStatus, len(c.Mappings))}
	for i, m := range c.Mappings {
		t.index[m.ID] = i
		t.status.Mappings[i].ID = m.ID
	}
	go t.writer()
	t.notify()
	return t
}
func (t *tracker) notify() {
	select {
	case t.dirty <- struct{}{}:
	default:
	}
}
func (t *tracker) snapshot() Status {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.status
	s.UpdatedAt = time.Now().Unix()
	s.Mappings = append([]MappingStatus(nil), s.Mappings...)
	return s
}
func (t *tracker) flush() {
	b, err := json.Marshal(t.snapshot())
	if err != nil {
		return
	}
	dir := filepath.Dir(t.path)
	f, err := os.CreateTemp(dir, ".reverse-status-")
	if err != nil {
		return
	}
	name := f.Name()
	defer os.Remove(name)
	if f.Chmod(0600) != nil {
		f.Close()
		return
	}
	if _, err = f.Write(append(b, '\n')); err != nil {
		f.Close()
		return
	}
	if f.Close() != nil {
		return
	}
	_ = os.Rename(name, t.path)
}
func (t *tracker) writer() {
	defer close(t.done)
	// Coalesce bursts of connection/datagram updates. Writing a status file
	// for every packet would turn network traffic into unbounded filesystem
	// work. The periodic snapshot also keeps offline liveness fresh.
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	t.flush()
	for {
		select {
		case <-t.dirty:
			select {
			case <-tick.C:
				t.flush()
			case <-t.stop:
				t.flush()
				return
			}
		case <-tick.C:
			t.flush()
		case <-t.stop:
			t.flush()
			return
		}
	}
}
func (t *tracker) finish() { t.setState("stopped", false, ""); close(t.stop); <-t.done }
func (t *tracker) setState(state string, online bool, code string) {
	t.mu.Lock()
	t.status.State = state
	t.status.Connected = online
	t.status.Error = code
	if !online {
		for i := range t.status.Mappings {
			t.status.Mappings[i].Listening = false
		}
	}
	t.mu.Unlock()
	t.notify()
}
func (t *tracker) heartbeat() {
	t.mu.Lock()
	t.status.LastHeartbeat = time.Now().Unix()
	t.mu.Unlock()
	t.notify()
}
func (t *tracker) listen(id string, on bool) {
	t.mu.Lock()
	i := t.index[id]
	t.status.Mappings[i].Listening = on
	t.mu.Unlock()
	t.notify()
}
func (t *tracker) active(id string, delta int) {
	t.mu.Lock()
	i := t.index[id]
	t.status.Mappings[i].Active += delta
	t.mu.Unlock()
	t.notify()
}
func (t *tracker) bytes(id string, rx, tx int) {
	t.mu.Lock()
	i := t.index[id]
	t.status.Mappings[i].RXBytes += uint64(rx)
	t.status.Mappings[i].TXBytes += uint64(tx)
	t.mu.Unlock()
}
func (t *tracker) success(id string) {
	t.mu.Lock()
	i := t.index[id]
	t.status.Mappings[i].LastSuccess = time.Now().Unix()
	t.status.Mappings[i].LastError = ""
	t.mu.Unlock()
	t.notify()
}
func (t *tracker) mapError(id, code string) {
	t.mu.Lock()
	i := t.index[id]
	changed := t.status.Mappings[i].LastError != code
	t.status.Mappings[i].LastError = code
	t.mu.Unlock()
	if changed {
		t.notify()
	}
}
