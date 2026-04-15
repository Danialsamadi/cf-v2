package service

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Cloudflare IP range data (translated from GetCloudflareIPs.ts)
// ---------------------------------------------------------------------------

// cloudflareIPsAll is the full set of known Cloudflare CIDR ranges.
var cloudflareIPsAll = []string{
	"23.227.37.0/24", "23.227.38.0/23", "23.227.60.0/24",
	"64.68.192.0/24", "65.110.63.0/24", "66.235.200.0/24",
	"68.67.65.0/24", "91.234.214.0/24",
	"103.21.244.0/24", "103.22.201.0/24", "103.22.202.0/23",
	"103.81.228.0/24",
	"104.16.0.0/13", "104.24.0.0/14", "104.28.0.0/15",
	"104.30.1.0/24", "104.30.2.0/23", "104.30.4.0/22",
	"104.30.8.0/21", "104.30.16.0/20", "104.30.32.0/19",
	"104.30.64.0/18", "104.30.128.0/17", "104.31.0.0/16",
	"108.162.192.0/20", "108.162.210.0/23", "108.162.212.0/23",
	"108.162.216.0/23", "108.162.218.0/24", "108.162.235.0/24",
	"108.162.236.0/22", "108.162.240.0/21", "108.162.248.0/23",
	"108.162.250.0/24", "108.162.255.0/24",
	"141.101.65.0/24", "141.101.66.0/23", "141.101.68.0/22",
	"141.101.72.0/22", "141.101.76.0/23", "141.101.82.0/23",
	"141.101.84.0/22", "141.101.90.0/24", "141.101.92.0/22",
	"141.101.96.0/21", "141.101.106.0/23", "141.101.108.0/23",
	"141.101.110.0/24", "141.101.112.0/20",
	"162.158.0.0/22", "162.158.4.0/23", "162.158.8.0/21",
	"162.158.16.0/20", "162.158.32.0/22", "162.158.36.0/23",
	"162.158.38.0/24", "162.158.40.0/21", "162.158.48.0/24",
	"162.158.51.0/24", "162.158.52.0/22", "162.158.56.0/22",
	"162.158.60.0/24", "162.158.62.0/23", "162.158.72.0/21",
	"162.158.80.0/23", "162.158.82.0/24", "162.158.84.0/22",
	"162.158.88.0/21", "162.158.96.0/21", "162.158.108.0/22",
	"162.158.112.0/23", "162.158.114.0/24", "162.158.117.0/24",
	"162.158.118.0/23", "162.158.124.0/22", "162.158.128.0/19",
	"162.158.160.0/20", "162.158.176.0/24", "162.158.178.0/23",
	"162.158.180.0/22", "162.158.184.0/22", "162.158.191.0/24",
	"162.158.192.0/22", "162.158.196.0/24", "162.158.198.0/23",
	"162.158.200.0/21", "162.158.208.0/22", "162.158.212.0/24",
	"162.158.214.0/23", "162.158.216.0/21", "162.158.224.0/20",
	"162.158.240.0/21", "162.158.248.0/22", "162.158.253.0/24",
	"162.158.255.0/24",
	"162.159.0.0/18", "162.159.64.0/21", "162.159.72.0/22",
	"162.159.76.0/23", "162.159.78.0/24", "162.159.128.0/17",
	"162.251.82.0/24",
	"172.64.0.0/15", "172.66.0.0/22", "172.66.40.0/21",
	"172.67.0.0/16",
	"172.68.0.0/19", "172.68.32.0/21", "172.68.40.0/22",
	"172.68.45.0/24", "172.68.46.0/23", "172.68.48.0/20",
	"172.68.64.0/20", "172.68.80.0/23", "172.68.83.0/24",
	"172.68.84.0/22", "172.68.88.0/21", "172.68.96.0/20",
	"172.68.112.0/21", "172.68.120.0/23", "172.68.123.0/24",
	"172.68.124.0/22", "172.68.128.0/21", "172.68.136.0/22",
	"172.68.140.0/23", "172.68.142.0/24", "172.68.144.0/21",
	"172.68.152.0/22", "172.68.161.0/24", "172.68.162.0/23",
	"172.68.164.0/22", "172.68.168.0/21", "172.68.176.0/23",
	"172.68.179.0/24", "172.68.180.0/22", "172.68.184.0/21",
	"172.68.196.0/22", "172.68.200.0/21", "172.68.208.0/21",
	"172.68.217.0/24", "172.68.218.0/23", "172.68.220.0/22",
	"172.68.224.0/20", "172.68.240.0/21", "172.68.248.0/22",
	"172.68.252.0/23", "172.68.255.0/24",
	"172.69.0.0/20", "172.69.16.0/24", "172.69.18.0/23",
	"172.69.20.0/22", "172.69.32.0/20", "172.69.48.0/24",
	"172.69.52.0/22", "172.69.56.0/21", "172.69.64.0/22",
	"172.69.72.0/21", "172.69.80.0/20", "172.69.96.0/21",
	"172.69.105.0/24", "172.69.106.0/23", "172.69.108.0/22",
	"172.69.112.0/21", "172.69.124.0/22", "172.69.128.0/20",
	"172.69.144.0/21", "172.69.156.0/22", "172.69.160.0/19",
	"172.69.192.0/20", "172.69.208.0/24", "172.69.210.0/23",
	"172.69.212.0/22", "172.69.216.0/21", "172.69.224.0/23",
	"172.69.227.0/24", "172.69.228.0/22", "172.69.232.0/21",
	"172.69.240.0/21", "172.69.248.0/24", "172.69.250.0/23",
	"172.69.252.0/22",
	"172.70.32.0/20", "172.70.48.0/23", "172.70.51.0/24",
	"172.70.52.0/22", "172.70.56.0/21", "172.70.80.0/20",
	"172.70.96.0/20", "172.70.112.0/22", "172.70.116.0/23",
	"172.70.120.0/21", "172.70.128.0/21", "172.70.136.0/23",
	"172.70.139.0/24", "172.70.140.0/22", "172.70.144.0/22",
	"172.70.148.0/23", "172.70.150.0/24", "172.70.152.0/22",
	"172.70.156.0/23", "172.70.158.0/24", "172.70.160.0/22",
	"172.70.172.0/22", "172.70.176.0/21", "172.70.185.0/24",
	"172.70.186.0/23", "172.70.188.0/22", "172.70.192.0/18",
	"172.71.0.0/24", "172.71.2.0/23", "172.71.4.0/22",
	"172.71.8.0/21", "172.71.16.0/23", "172.71.20.0/22",
	"172.71.24.0/21", "172.71.80.0/21", "172.71.88.0/23",
	"172.71.90.0/24", "172.71.92.0/22", "172.71.96.0/21",
	"172.71.108.0/22", "172.71.112.0/20", "172.71.128.0/21",
	"172.71.137.0/24", "172.71.138.0/23", "172.71.140.0/22",
	"172.71.144.0/20", "172.71.160.0/19", "172.71.192.0/18",
	"173.245.49.0/24", "173.245.54.0/24", "173.245.58.0/23",
	"173.245.63.0/24",
	"185.146.172.0/23",
	"188.114.96.0/22", "188.114.100.0/24", "188.114.102.0/23",
	"188.114.106.0/23", "188.114.108.0/24", "188.114.111.0/24",
	"190.93.240.0/20",
	"195.242.122.0/23",
	"197.234.240.0/22",
	"198.41.129.0/24", "198.41.192.0/20", "198.41.208.0/23",
	"198.41.211.0/24", "198.41.212.0/24", "198.41.214.0/23",
	"198.41.216.0/21", "198.41.224.0/21", "198.41.232.0/23",
	"198.41.236.0/22", "198.41.240.0/23", "198.41.242.0/24",
	"198.217.251.0/24",
	"199.27.128.0/22", "199.27.132.0/24",
}

// cloudflareIPsDefault is the curated "UK datacenter" subset (smaller, faster to scan).
var cloudflareIPsDefault = []string{
	"5.226.179.0/24", "5.226.181.0/24",
	"8.12.10.0/24", "12.221.133.0/24",
	"23.141.168.0/24", "23.178.112.0/24", "23.247.163.0/24",
	"31.43.179.0/24", "38.67.242.0/24",
	"45.8.104.0/22", "45.8.211.0/24", "45.12.30.0/23",
	"45.14.174.0/24", "45.80.111.0/24", "45.84.59.0/24",
	"45.85.118.0/23", "45.87.175.0/24", "45.94.169.0/24",
	"45.95.241.0/24", "45.131.4.0/22", "45.131.208.0/22",
	"45.133.247.0/24", "45.137.99.0/24", "45.142.120.0/24",
	"45.145.28.0/23", "45.158.56.0/24", "45.159.216.0/22",
	"64.21.2.0/24", "65.205.150.0/24",
	"66.81.247.0/24", "66.81.255.0/24", "72.52.113.0/24",
	"80.94.83.0/24", "89.47.56.0/23", "89.116.250.0/24",
	"89.207.18.0/24", "91.192.107.0/24", "91.193.58.0/23",
	"91.195.110.0/24", "91.199.81.0/24", "91.221.116.0/24",
	"93.114.64.0/23", "95.214.178.0/23",
	"103.11.212.0/24", "103.11.214.0/24", "103.79.228.0/23",
	"103.112.176.0/24", "103.121.59.0/24", "103.156.22.0/23",
	"103.160.204.0/24", "103.168.172.0/24", "103.169.142.0/24",
	"103.172.111.0/24", "103.204.13.0/24", "103.244.116.0/22",
	"104.234.158.0/24", "104.254.140.0/24",
	"108.165.216.0/24",
	"123.253.174.0/24",
	"141.11.194.0/23", "141.193.213.0/24",
	"146.19.22.0/24", "147.78.121.0/24", "147.78.140.0/24",
	"147.185.161.0/24",
	"154.51.129.0/24", "154.51.160.0/24",
	"154.83.2.0/24", "154.83.22.0/24", "154.83.30.0/24",
	"154.84.14.0/23", "154.84.16.0/24", "154.84.20.0/23",
	"154.84.24.0/24", "154.84.26.0/23", "154.84.175.0/24",
	"154.85.9.0/24", "154.85.99.0/24", "154.219.3.0/24",
	"156.237.4.0/23", "156.238.14.0/24", "156.238.18.0/23",
	"156.239.152.0/23", "156.239.154.0/24",
	"159.112.235.0/24", "159.246.55.0/24", "160.153.0.0/24",
	"162.44.104.0/22", "168.100.6.0/24",
	"170.114.45.0/24", "170.114.46.0/24", "170.114.52.0/24",
	"172.83.72.0/23", "172.83.76.0/24",
	"174.136.134.0/24", "176.126.206.0/23",
	"185.7.190.0/23", "185.18.250.0/24", "185.38.135.0/24",
	"185.59.218.0/24", "185.67.124.0/24", "185.72.49.0/24",
	"185.109.21.0/24", "185.135.9.0/24", "185.148.104.0/22",
	"185.162.228.0/22", "185.170.166.0/24", "185.174.138.0/24",
	"185.176.24.0/24", "185.176.26.0/24", "185.193.28.0/22",
	"185.201.139.0/24", "185.207.92.0/24",
	"185.213.240.0/24", "185.213.243.0/24",
	"185.221.160.0/24", "185.234.22.0/24", "185.238.228.0/24",
	"185.244.106.0/24",
	"188.42.88.0/23", "188.244.122.0/24",
	"191.101.251.0/24",
	"192.65.217.0/24", "192.133.11.0/24",
	"193.9.49.0/24", "193.16.63.0/24", "193.17.206.0/24",
	"193.67.144.0/24", "193.188.14.0/24", "193.227.99.0/24",
	"194.1.194.0/24", "194.36.49.0/24", "194.36.55.0/24",
	"194.36.216.0/22", "194.40.240.0/23", "194.53.53.0/24",
	"194.152.44.0/24", "194.169.194.0/24",
	"195.85.23.0/24", "195.85.59.0/24", "195.137.167.0/24",
	"195.245.221.0/24",
	"196.13.241.0/24", "196.207.45.0/24",
	"199.60.103.0/24", "199.181.197.0/24", "199.212.90.0/24",
	"202.82.250.0/24",
	"203.13.32.0/24", "203.17.126.0/24", "203.19.222.0/24",
	"203.22.223.0/24", "203.23.103.0/24", "203.23.104.0/24",
	"203.23.106.0/24", "203.24.102.0/23", "203.24.108.0/23",
	"203.28.8.0/23", "203.29.52.0/22", "203.30.188.0/22",
	"203.32.120.0/23", "203.34.28.0/24", "203.34.80.0/24",
	"203.55.107.0/24", "203.89.5.0/24", "203.107.173.0/24",
	"203.193.21.0/24",
	"204.62.141.0/24", "204.68.111.0/24", "204.209.72.0/23",
	"205.233.181.0/24", "206.196.23.0/24", "207.189.149.0/24",
	"208.100.60.0/24",
	"212.24.127.0/24", "212.110.134.0/23", "212.239.86.0/24",
	"216.120.180.0/23",
}

// ---------------------------------------------------------------------------
// CIDR utilities
// ---------------------------------------------------------------------------

// CIDRIPCount returns the number of host IPs in a CIDR block.
// For a /32 (single host) it returns 1; for /24 it returns 256, etc.
func CIDRIPCount(cidr string) int {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Treat plain IPs as /32
		return 1
	}
	ones, bits := ipNet.Mask.Size()
	return 1 << (bits - ones)
}

// TotalIPCount returns the sum of all IPs across a slice of CIDR strings.
func TotalIPCount(cidrs []string) int {
	total := 0
	for _, c := range cidrs {
		total += CIDRIPCount(c)
	}
	return total
}

// GetCIDRs returns the CIDR list for the given mode.
// customCIDR is only used when mode == ModeCustom.
func GetCIDRs(mode IPMode, customCIDR string) []string {
	switch mode {
	case ModeAllIPs:
		return cloudflareIPsAll
	case ModeDefaultIPs:
		return cloudflareIPsDefault
	case ModeCustom:
		return parseCIDRList(customCIDR)
	}
	return cloudflareIPsDefault
}

// parseCIDRList splits a newline/space/comma-separated text into CIDR strings.
func parseCIDRList(text string) []string {
	text = strings.ReplaceAll(text, ",", "\n")
	lines := strings.Fields(text)
	var out []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		out = append(out, l)
	}
	return out
}

// randomIPFromCIDR picks a random IP address within the given CIDR.
func randomIPFromCIDR(cidr string) (string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Maybe it's already a plain IP
		ip := net.ParseIP(strings.TrimSpace(cidr))
		if ip == nil {
			return "", fmt.Errorf("invalid CIDR or IP: %s", cidr)
		}
		return ip.String(), nil
	}
	// Convert network address to uint32
	base := binary.BigEndian.Uint32(ipNet.IP.To4())
	ones, bits := ipNet.Mask.Size()
	size := uint32(1) << uint(bits-ones)
	if size <= 2 {
		return ipNet.IP.String(), nil
	}
	// Skip .0 and .255
	offset := uint32(rand.Intn(int(size-2))) + 1
	ipInt := base + offset
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipInt)
	return ip.String(), nil
}

// ---------------------------------------------------------------------------
// IP testing (matches TestIp.ts logic)
// ---------------------------------------------------------------------------

// TestIP checks whether a Cloudflare IP is reachable by sending HTTPS requests.
// A "Network Error" (i.e. TCP connection reset / TLS error) from the edge is
// treated as success, because it means the Cloudflare edge responded.
// A timeout means the IP is dead.
// Returns a populated IPResult on success, or nil on failure.
func TestIP(ip string, timeoutMs int, pingCount int) *IPResult {
	client := &http.Client{
		Timeout: time.Duration(timeoutMs) * time.Millisecond,
		// Don't follow redirects – we just want the first response / error.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			// Disable keep-alives; we're testing raw connectivity.
			DisableKeepAlives: true,
		},
	}

	url := fmt.Sprintf("https://%s/", ip)
	successCount := 0
	var totalDuration time.Duration

	for i := 0; i <= pingCount; i++ {
		start := time.Now()
		_, err := client.Get(url)
		elapsed := time.Since(start)

		if err != nil {
			errStr := err.Error()
			// These indicate the remote edge actually responded (connection
			// reset, TLS handshake, 4xx, etc.) – same logic as the JS version.
			if strings.Contains(errStr, "connection reset") ||
				strings.Contains(errStr, "EOF") ||
				strings.Contains(errStr, "tls") ||
				strings.Contains(errStr, "certificate") ||
				strings.Contains(errStr, "connection refused") ||
				strings.Contains(errStr, "remote error") {
				successCount++
				if i > 0 {
					totalDuration += elapsed
				}
				continue
			}
			// Timeout or truly unreachable → fail fast
			return nil
		}
		// Got an HTTP response (301, 400, etc.) → edge is alive
		successCount++
		if i > 0 {
			totalDuration += elapsed
		}
	}

	if successCount < pingCount {
		return nil
	}

	avgMs := 0
	if pingCount > 0 {
		avgMs = int(totalDuration.Milliseconds()) / pingCount
	}
	return &IPResult{IP: ip, Latency: avgMs}
}

// ---------------------------------------------------------------------------
// Weighted sampling helpers (matches softmin / sampleFromDistribution in .ts)
// ---------------------------------------------------------------------------

// softmin computes a softmax over the negated values so that lower latency →
// higher weight.
func softmin(values []float64) []float64 {
	if len(values) == 0 {
		return nil
	}
	min := values[0]
	for _, v := range values[1:] {
		if v < min {
			min = v
		}
	}
	out := make([]float64, len(values))
	sum := 0.0
	for i, v := range values {
		out[i] = math.Exp(min - v)
		sum += out[i]
	}
	for i := range out {
		out[i] /= sum
	}
	return out
}

// SampleWeightedIP picks a CIDR range proportional to the given weights and
// returns a random IP within it.
func SampleWeightedIP(cidrs []string, weights []float64) (string, error) {
	if len(cidrs) == 0 {
		return "", fmt.Errorf("no CIDRs provided")
	}
	if len(weights) != len(cidrs) {
		// Uniform if weights don't match
		return randomIPFromCIDR(cidrs[rand.Intn(len(cidrs))])
	}
	r := rand.Float64()
	cumulative := 0.0
	for i, w := range weights {
		cumulative += w
		if r <= cumulative {
			return randomIPFromCIDR(cidrs[i])
		}
	}
	return randomIPFromCIDR(cidrs[len(cidrs)-1])
}

// CIDRWeights returns weights proportional to the sqrt of each CIDR's IP count
// (matching the ^0.2 scaling in the JS source).
func CIDRWeights(cidrs []string) []float64 {
	w := make([]float64, len(cidrs))
	sum := 0.0
	for i, c := range cidrs {
		w[i] = math.Pow(float64(CIDRIPCount(c)), 0.2)
		sum += w[i]
	}
	for i := range w {
		w[i] /= sum
	}
	return w
}

// LatencyWeights returns softmin-normalised weights from an IPResult slice.
func LatencyWeights(results []IPResult) []float64 {
	vals := make([]float64, len(results))
	for i, r := range results {
		vals[i] = float64(r.Latency) / 500.0
	}
	return softmin(vals)
}

// SampleIPsWeighted samples n IPs (with replacement) from results, favouring
// lower latency ones.  Used for populating the Worker clean-IP list.
func SampleIPsWeighted(results []IPResult, n int) []string {
	if len(results) == 0 {
		return nil
	}
	weights := LatencyWeights(results)
	// Build cumulative
	cum := make([]float64, len(weights))
	cum[0] = weights[0]
	for i := 1; i < len(weights); i++ {
		cum[i] = cum[i-1] + weights[i]
	}
	out := make([]string, n)
	for i := 0; i < n; i++ {
		r := rand.Float64()
		idx := 0
		for idx < len(cum)-1 && r > cum[idx] {
			idx++
		}
		out[i] = results[idx].IP
	}
	return out
}
