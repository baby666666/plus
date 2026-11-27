package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

const (
	protocolVersion = 2
	maxMappings     = 32
	maxSessions     = 64
	maxUDPSessions  = 32
	maxMessage      = 8192
	maxDatagram     = 65507
)

type Mapping struct {
	ID       string   `json:"id"`
	Protocol string   `json:"protocol"`
	Listen   string   `json:"listen"`
	Target   string   `json:"target"`
	Allow    []string `json:"allow"`
	networks []*net.IPNet
}

type Config struct {
	Mode       string    `json:"mode"`
	Token      string    `json:"token"`
	Control    string    `json:"control"`
	Socks      string    `json:"socks,omitempty"`
	StatusFile string    `json:"status_file"`
	TargetMark uint32    `json:"target_mark,omitempty"`
	Mappings   []Mapping `json:"mappings"`
	fileHash   string
	digest     string
}

func decodeStrict(data []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing_json")
	}
	return nil
}

func loadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("config_unreadable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 65536 {
		return nil, errors.New("invalid_config_file")
	}
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(b) > 65536 {
		return nil, errors.New("invalid_config_file")
	}
	var c Config
	if decodeStrict(b, &c) != nil {
		return nil, errors.New("invalid_config_json")
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	c.fileHash = hex.EncodeToString(h[:])
	return &c, nil
}

func endpoint(value string, allowWildcard bool) (net.IP, int, error) {
	h, p, err := net.SplitHostPort(value)
	if err != nil {
		return nil, 0, errors.New("invalid_endpoint")
	}
	ip := net.ParseIP(h)
	port, err := strconv.Atoi(p)
	if ip == nil || ip.To4() == nil || ip.String() != h || err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != p {
		return nil, 0, errors.New("invalid_endpoint")
	}
	ip = ip.To4()
	if (!allowWildcard && ip.IsUnspecified()) || ip.IsMulticast() || ip.Equal(net.IPv4bcast) || (ip[0] == 0 && !ip.IsUnspecified()) || ip[0] >= 224 {
		return nil, 0, errors.New("invalid_endpoint")
	}
	return ip, port, nil
}

func validHex(s string, bytes int) bool {
	if len(s) != bytes*2 {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == bytes && hex.EncodeToString(b) == s
}

func (c *Config) validate() error {
	if c.Mode != "server" && c.Mode != "client" {
		return errors.New("invalid_mode")
	}
	if !validHex(c.Token, 32) {
		return errors.New("invalid_token")
	}
	_, controlPort, err := endpoint(c.Control, false)
	if err != nil {
		return errors.New("invalid_control_endpoint")
	}
	if c.Mode == "client" {
		ip, _, err := endpoint(c.Socks, false)
		if err != nil || !ip.IsLoopback() {
			return errors.New("invalid_socks_endpoint")
		}
	} else if c.Socks != "" || c.TargetMark != 0 {
		return errors.New("invalid_server_options")
	}
	if !filepath.IsAbs(c.StatusFile) || filepath.Clean(c.StatusFile) != c.StatusFile {
		return errors.New("invalid_status_path")
	}
	if len(c.Mappings) < 1 || len(c.Mappings) > maxMappings {
		return errors.New("invalid_mapping_count")
	}
	ids, listeners := map[string]bool{}, map[string]bool{}
	for i := range c.Mappings {
		m := &c.Mappings[i]
		n, err := strconv.Atoi(m.ID)
		if err != nil || n < 1 || n > maxMappings || strconv.Itoa(n) != m.ID || ids[m.ID] {
			return errors.New("invalid_mapping_id")
		}
		ids[m.ID] = true
		if m.Protocol != "tcp" && m.Protocol != "udp" {
			return errors.New("invalid_mapping_protocol")
		}
		_, p, err := endpoint(m.Listen, true)
		if err != nil {
			return errors.New("invalid_mapping_listener")
		}
		// The firmware deliberately reserves the control port across all local
		// addresses. A wildcard TCP mapping must never shadow its own control.
		if m.Protocol == "tcp" && p == controlPort {
			return errors.New("control_port_conflict")
		}
		key := m.Protocol + ":" + strconv.Itoa(p)
		if listeners[key] {
			return errors.New("duplicate_mapping_listener")
		}
		listeners[key] = true
		if _, _, err := endpoint(m.Target, false); err != nil {
			return errors.New("invalid_mapping_target")
		}
		if len(m.Allow) < 1 || len(m.Allow) > 16 {
			return errors.New("invalid_source_list")
		}
		m.networks = nil
		seen := map[string]bool{}
		for j, value := range m.Allow {
			ip, network, err := net.ParseCIDR(value)
			if err != nil || ip.To4() == nil {
				return errors.New("invalid_source_network")
			}
			if _, bits := network.Mask.Size(); bits != 32 {
				return errors.New("invalid_source_network")
			}
			canonical := network.String()
			if seen[canonical] {
				return errors.New("duplicate_source_network")
			}
			seen[canonical] = true
			m.Allow[j] = canonical
			m.networks = append(m.networks, network)
		}
		sort.Strings(m.Allow)
	}
	sort.Slice(c.Mappings, func(i, j int) bool {
		a, _ := strconv.Atoi(c.Mappings[i].ID)
		b, _ := strconv.Atoi(c.Mappings[j].ID)
		return a < b
	})
	b, err := json.Marshal(c.Mappings)
	if err != nil {
		return fmt.Errorf("invalid_mappings")
	}
	h := sha256.Sum256(b)
	c.digest = hex.EncodeToString(h[:])
	return nil
}

func (m Mapping) allowed(addr net.Addr) bool {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return false
	}
	for _, n := range m.networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
