package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type occupiedSocket struct {
	protocol string
	ip       net.IP
	port     int
	inode    string
}

func procAddress(encoded string) (net.IP, error) {
	b, err := hex.DecodeString(encoded)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return nil, errors.New("invalid_proc_address")
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+3] = b[i+3], b[i]
		b[i+1], b[i+2] = b[i+2], b[i+1]
	}
	return net.IP(b), nil
}
func socketInventory() ([]occupiedSocket, error) {
	var sockets []occupiedSocket
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		f, err := os.Open("/proc/net/" + name)
		if err != nil {
			if strings.HasSuffix(name, "6") && os.IsNotExist(err) {
				continue
			}
			return nil, errors.New("port_inventory_failed")
		}
		scan := bufio.NewScanner(f)
		scan.Scan()
		for scan.Scan() {
			fields := strings.Fields(scan.Text())
			if len(fields) < 10 {
				f.Close()
				return nil, errors.New("port_inventory_failed")
			}
			proto := strings.TrimSuffix(name, "6")
			if proto == "tcp" && fields[3] != "0A" {
				continue
			}
			parts := strings.Split(fields[1], ":")
			if len(parts) != 2 {
				f.Close()
				return nil, errors.New("port_inventory_failed")
			}
			ip, err := procAddress(parts[0])
			if err != nil {
				f.Close()
				return nil, errors.New("port_inventory_failed")
			}
			p, err := strconv.ParseUint(parts[1], 16, 16)
			if err != nil {
				f.Close()
				return nil, errors.New("port_inventory_failed")
			}
			sockets = append(sockets, occupiedSocket{proto, ip, int(p), fields[9]})
		}
		err = scan.Err()
		f.Close()
		if err != nil {
			return nil, errors.New("port_inventory_failed")
		}
	}
	return sockets, nil
}
func ownedSockets(pid int) (map[string]bool, error) {
	owned := map[string]bool{}
	if pid == 0 {
		return owned, nil
	}
	dir := "/proc/" + strconv.Itoa(pid) + "/fd"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, errors.New("exclude_pid_unavailable")
	}
	for _, entry := range entries {
		value, err := os.Readlink(filepath.Join(dir, entry.Name()))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, errors.New("socket_owner_unavailable")
		}
		if strings.HasPrefix(value, "socket:[") && strings.HasSuffix(value, "]") {
			owned[strings.TrimSuffix(strings.TrimPrefix(value, "socket:["), "]")] = true
		}
	}
	return owned, nil
}
func overlaps(a, b net.IP) bool { return a.IsUnspecified() || b.IsUnspecified() || a.Equal(b) }
func checkPorts(c *Config, excludePID int) error {
	if c.Mode != "server" {
		return nil
	}
	sockets, err := socketInventory()
	if err != nil {
		return err
	}
	owned, err := ownedSockets(excludePID)
	if err != nil {
		return err
	}
	check := func(proto, address string, bind bool) error {
		ip, port, _ := endpoint(address, true)
		excluded := false
		for _, s := range sockets {
			if s.protocol == proto && s.port == port && overlaps(ip, s.ip) {
				if !owned[s.inode] {
					return fmt.Errorf("port_in_use: %s/%d", proto, port)
				}
				excluded = true
			}
		}
		if !bind || excluded {
			return nil
		}
		if proto == "tcp" {
			listener, err := net.Listen("tcp4", address)
			if err != nil {
				return fmt.Errorf("port_unavailable: tcp/%d", port)
			}
			return listener.Close()
		}
		addr, err := net.ResolveUDPAddr("udp4", address)
		if err != nil {
			return errors.New("invalid_mapping_listener")
		}
		listener, err := net.ListenUDP("udp4", addr)
		if err != nil {
			return fmt.Errorf("port_unavailable: udp/%d", port)
		}
		return listener.Close()
	}
	// A projected WG gateway need not be assigned yet. Its control socket is
	// checked against actual occupied endpoints; startup performs the bind.
	if err := check("tcp", c.Control, false); err != nil {
		return err
	}
	for _, m := range c.Mappings {
		if err := check(m.Protocol, m.Listen, true); err != nil {
			return err
		}
	}
	return nil
}
