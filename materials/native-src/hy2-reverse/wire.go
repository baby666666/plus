package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type message struct {
	Version int    `json:"version"`
	Kind    string `json:"kind"`
	Token   string `json:"token,omitempty"`
	Digest  string `json:"digest,omitempty"`
	Session string `json:"session,omitempty"`
	Job     string `json:"job,omitempty"`
	Mapping string `json:"mapping,omitempty"`
	OK      bool   `json:"ok,omitempty"`
	Error   string `json:"error,omitempty"`
}

func readMessage(r io.Reader) (message, error) {
	var m message
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return m, err
	}
	n := binary.BigEndian.Uint32(head[:])
	if n < 2 || n > maxMessage {
		return m, errors.New("invalid_frame")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return m, err
	}
	if err := decodeStrict(b, &m); err != nil {
		return m, errors.New("invalid_message")
	}
	if m.Version != protocolVersion {
		return m, errors.New("protocol_mismatch")
	}
	return m, nil
}
func writeMessage(w io.Writer, m message) error {
	m.Version = protocolVersion
	b, err := json.Marshal(m)
	if err != nil || len(b) > maxMessage {
		return errors.New("invalid_message")
	}
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], uint32(len(b)))
	if err = writeAll(w, head[:]); err != nil {
		return err
	}
	return writeAll(w, b)
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n > 0 {
			b = b[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("random_source_failed")
	}
	return hex.EncodeToString(b[:])
}
func authenticated(got, want string) bool {
	return len(got) == 64 && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

type controlWriter struct {
	mu   sync.Mutex
	conn net.Conn
}

func (w *controlWriter) send(m message) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_ = w.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err := writeMessage(w.conn, m)
	_ = w.conn.SetWriteDeadline(time.Time{})
	return err
}

func readDatagram(r io.Reader) ([]byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(head[:]))
	if n > maxDatagram {
		return nil, errors.New("invalid_datagram")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}
func writeDatagram(w io.Writer, b []byte) error {
	if len(b) > maxDatagram {
		return errors.New("invalid_datagram")
	}
	var head [2]byte
	binary.BigEndian.PutUint16(head[:], uint16(len(b)))
	if err := writeAll(w, head[:]); err != nil {
		return err
	}
	return writeAll(w, b)
}

var safeCodes = map[string]bool{
	"authentication_failed": true, "configuration_mismatch": true, "client_already_online": true,
	"mapping_listen_failed": true, "session_unavailable": true, "invalid_work": true,
	"target_unreachable": true, "target_timeout": true, "target_mark_failed": true,
	"socks_unreachable": true, "socks_rejected": true, "control_unreachable": true,
	"control_lost": true, "work_unreachable": true, "work_timeout": true, "work_rejected": true,
	"session_limit": true, "udp_queue_full": true, "udp_error": true, "transfer_failed": true,
	"protocol_error": true, "source_denied": true,
}

func safeCode(code string) string {
	if safeCodes[code] {
		return code
	}
	return "protocol_error"
}

type codedError string

func (e codedError) Error() string { return string(e) }
func errorCode(err error, fallback string) string {
	var code codedError
	if errors.As(err, &code) {
		return safeCode(string(code))
	}
	return fallback
}
