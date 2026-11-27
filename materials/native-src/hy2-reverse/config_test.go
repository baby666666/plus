package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testConfig(t *testing.T, mode, control, proxy string, mappings []Mapping) *Config {
	t.Helper()
	c := &Config{Mode: mode, Token: strings.Repeat("a1", 32), Control: control, Socks: proxy, StatusFile: filepath.Join(t.TempDir(), "status.json"), Mappings: mappings}
	path := filepath.Join(t.TempDir(), "config.json")
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func TestConfigurationValidationAndDigest(t *testing.T) {
	base := Mapping{ID: "1", Protocol: "tcp", Listen: "0.0.0.0:18080", Target: "192.168.62.1:80", Allow: []string{"10.2.3.4/8", "192.168.1.0/24"}}
	a := testConfig(t, "server", "10.177.1.1:49871", "", []Mapping{base})
	base.Allow = []string{"192.168.1.0/24", "10.0.0.0/8"}
	b := testConfig(t, "client", "10.177.1.1:49871", "127.77.1.1:1080", []Mapping{base})
	if a.digest != b.digest {
		t.Fatal("same canonical mappings have different digests")
	}
	b.Mappings[0].Target = "192.168.62.2:80"
	if b.validate() != nil || a.digest == b.digest {
		t.Fatal("target must be bound to mapping digest")
	}
	if !validHex(a.fileHash, 32) {
		t.Fatal("missing raw config fingerprint")
	}
	for _, bad := range []struct {
		name   string
		change func(*Config)
	}{
		{"wildcard_control", func(c *Config) { c.Control = "0.0.0.0:49871" }},
		{"remote_socks", func(c *Config) { c.Mode = "client"; c.Socks = "10.1.1.1:1080" }},
		{"bad_token", func(c *Config) { c.Token = "password" }},
		{"duplicate_id", func(c *Config) { c.Mappings = append(c.Mappings, c.Mappings[0]) }},
		{"control_conflict", func(c *Config) { c.Mappings[0].Listen = "0.0.0.0:49871" }},
		{"multicast_target", func(c *Config) { c.Mappings[0].Target = "224.1.2.3:80" }},
		{"noncanonical_target", func(c *Config) { c.Mappings[0].Target = "192.168.062.1:80" }},
		{"hostname_target", func(c *Config) { c.Mappings[0].Target = "example.com:80" }},
		{"empty_acl", func(c *Config) { c.Mappings[0].Allow = nil }},
		{"mapped_v6_acl", func(c *Config) { c.Mappings[0].Allow = []string{"::ffff:127.0.0.1/128"} }},
	} {
		t.Run(bad.name, func(t *testing.T) {
			raw, _ := json.Marshal(a)
			var c Config
			_ = json.Unmarshal(raw, &c)
			bad.change(&c)
			if c.validate() == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestConfigFileFingerprintAndStrictFields(t *testing.T) {
	c := testConfig(t, "server", "127.0.0.1:49871", "", []Mapping{{ID: "1", Protocol: "tcp", Listen: "0.0.0.0:18080", Target: "127.0.0.1:80", Allow: []string{"0.0.0.0/0"}}})
	raw, _ := json.Marshal(c)
	raw = append(raw, '\n')
	path := filepath.Join(t.TempDir(), "config.json")
	_ = os.WriteFile(path, raw, 0600)
	loaded, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(raw)
	if loaded.fileHash != hex.EncodeToString(expected[:]) {
		t.Fatal("config_sha256 does not match exact bytes")
	}
	raw = []byte(strings.TrimSpace(string(raw)))
	raw = append(raw[:len(raw)-1], []byte(",\"unexpected\":true}")...)
	_ = os.WriteFile(path, raw, 0600)
	if _, err = loadConfig(path); err == nil {
		t.Fatal("unknown config field accepted")
	}
}
