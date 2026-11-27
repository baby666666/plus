package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestPortOwnerHelper(t *testing.T) {
	if os.Getenv("NR_REVERSE_PORT_HELPER") != "1" {
		return
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	fmt.Println(l.Addr().String())
	conn, _ := l.Accept()
	if conn != nil {
		conn.Close()
	}
}

func TestPortPreflightRejectsOtherOwnersAndAllowsVerifiedWorker(t *testing.T) {
	busy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	c := testConfig(t, "server", freeAddress(t, "tcp"), "", []Mapping{{ID: "1", Protocol: "tcp", Listen: busy.Addr().String(), Target: freeAddress(t, "tcp"), Allow: []string{"0.0.0.0/0"}}})
	if checkPorts(c, 0) == nil {
		t.Fatal("occupied port not detected")
	}
	if err = checkPorts(c, os.Getpid()); err != nil {
		t.Fatalf("verified owner's port rejected: %v", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestPortOwnerHelper$")
	cmd.Env = append(os.Environ(), "NR_REVERSE_PORT_HELPER=1")
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Start() != nil {
		t.Fatal("helper start")
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line, err := bufio.NewReader(pipe).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	c.Mappings[0].Listen = strings.TrimSpace(line)
	if err = c.validate(); err != nil {
		t.Fatal(err)
	}
	if checkPorts(c, os.Getpid()) == nil {
		t.Fatal("unrelated owner excluded")
	}
	if err = checkPorts(c, cmd.Process.Pid); err != nil {
		t.Fatalf("actual owner rejected: %v", err)
	}
}

func TestPortPreflightChecksUDPAndIPv6AndProjectedControl(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	c := testConfig(t, "server", "10.254.254.254:49871", "", []Mapping{{ID: "1", Protocol: "udp", Listen: udp.LocalAddr().String(), Target: "127.0.0.1:9999", Allow: []string{"0.0.0.0/0"}}})
	if checkPorts(c, 0) == nil {
		t.Fatal("UDP port conflict ignored")
	}
	if err = checkPorts(c, os.Getpid()); err != nil {
		t.Fatalf("projected control address rejected: %v", err)
	}
	v6, err := net.Listen("tcp6", "[::]:0")
	if err != nil {
		t.Skip("IPv6 unavailable")
	}
	defer v6.Close()
	port := v6.Addr().(*net.TCPAddr).Port
	c.Mappings[0].Protocol = "tcp"
	c.Mappings[0].Listen = "0.0.0.0:" + strconv.Itoa(port)
	if err = c.validate(); err != nil {
		t.Fatal(err)
	}
	if checkPorts(c, 0) == nil {
		t.Fatal("IPv6 wildcard collision ignored")
	}
}
