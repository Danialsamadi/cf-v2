// Package service contains all the core business logic for V2ray-Cloudflare GUI.
package service

// IPResult holds a tested Cloudflare IP and its measured latency in milliseconds.
type IPResult struct {
	IP      string
	Latency int // ms
}

// IPMode controls which set of Cloudflare IPs to use.
type IPMode int

const (
	// ModeAllIPs uses the full Cloudflare IP list (global ranges).
	ModeAllIPs IPMode = iota
	// ModeDefaultIPs uses the curated "UK datacenter" subset (default).
	ModeDefaultIPs
	// ModeCustom uses custom CIDR ranges supplied by the user.
	ModeCustom
)

// ScanConfig holds all parameters for an IP scan run.
type ScanConfig struct {
	Mode       IPMode
	CustomCIDR string // newline-separated CIDR ranges, used when Mode == ModeCustom
	MaxIPs     int    // stop after finding this many valid IPs
	PingCount  int    // number of pings per IP
	TimeoutMs  int    // per-ping timeout in milliseconds
}

// VMessConfig represents a minimal VMess proxy configuration.
type VMessConfig struct {
	PS   string `json:"ps"`
	Add  string `json:"add"` // server address (Cloudflare IP)
	Port int    `json:"port"`
	ID   string `json:"id"` // UUID
	Aid  int    `json:"aid"`
	Net  string `json:"net"`  // ws or grpc
	Type string `json:"type"` // none
	Host string `json:"host"` // SNI / Host header
	Path string `json:"path"`
	TLS  string `json:"tls"` // "tls"
	SNI  string `json:"sni"`
	FP   string `json:"fp"` // fingerprint (browser UA)
	ALPN string `json:"alpn"`
}
