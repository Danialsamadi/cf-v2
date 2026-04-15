package service

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
)

// httsPorts are the Cloudflare HTTPS ports that support TLS proxying.
var httpsPorts = map[int]bool{
	443:  true,
	2053: true,
	2083: true,
	2087: true,
	2096: true,
	8443: true,
}

// alpnOptions mirrors the default ALPN list from the web app.
var alpnOptions = []string{"h2", "http/1.1", "h2,http/1.1"}

// fpOptions mirrors the default fingerprint (user-agent) list.
var fpOptions = []string{
	"chrome", "firefox", "safari", "random", "randomized",
	"ios", "android", "edge",
}

// ---------------------------------------------------------------------------
// VMess helpers
// ---------------------------------------------------------------------------

// GenerateDefaultVMessConfigs creates a slice of ready-to-use VMess configs
// using the supplied clean Cloudflare IPs.  These are "generated" configs –
// no user-supplied base config is needed.
func GenerateDefaultVMessConfigs(cleanIPs []IPResult, count int) []string {
	if len(cleanIPs) == 0 || count == 0 {
		return nil
	}
	weights := LatencyWeights(cleanIPs)
	var results []string

	// Pick common Cloudflare-compatible SNI hosts
	hosts := []string{
		"discord.com", "cloudflare.com", "nginx.com",
		"cdnjs.com", "vimeo.com", "spotify.com",
	}

	for i := 0; i < count; i++ {
		// Sample a clean IP weighted by latency
		ipIdx := weightedIndex(weights)
		ip := cleanIPs[ipIdx].IP

		host := hosts[rand.Intn(len(hosts))]
		alpn := alpnOptions[rand.Intn(len(alpnOptions))]
		fp := fpOptions[rand.Intn(len(fpOptions))]

		conf := VMessConfig{
			PS:   fmt.Sprintf("%d-CF-Clean-vmess-ws-%s-%s", i+1, fp, alpn),
			Add:  ip,
			Port: 443,
			ID:   newUUID(),
			Aid:  0,
			Net:  "ws",
			Type: "none",
			Host: host,
			Path: "/",
			TLS:  "tls",
			SNI:  host,
			FP:   fp,
			ALPN: alpn,
		}

		encoded, err := encodeVMess(conf)
		if err == nil {
			results = append(results, encoded)
		}
	}
	return results
}

// ChangeConfigs rewrites existing VMess/VLESS/Trojan configs by swapping in
// clean Cloudflare IPs.  rawConfigs is a newline-separated URI list.
func ChangeConfigs(rawConfigs string, cleanIPs []IPResult, count int, alpns []string, fps []string) []string {
	if len(alpns) == 0 {
		alpns = alpnOptions
	}
	if len(fps) == 0 {
		fps = fpOptions
	}

	// Parse all configs from the raw text
	vmess, vless, trojan := extractVMessConfigs(rawConfigs), extractURLConfigs(rawConfigs, "vless"), extractURLConfigs(rawConfigs, "trojan")
	allConfigs := append(append(vmess, vless...), trojan...)

	if len(allConfigs) == 0 || len(cleanIPs) == 0 {
		return nil
	}

	weights := LatencyWeights(cleanIPs)
	ips := make([]string, len(cleanIPs))
	for i, r := range cleanIPs {
		ips[i] = r.IP
	}

	var out []string
	max := 10 * count
	idx := 0

	for count > 0 && max > 0 {
		base := allConfigs[rand.Intn(len(allConfigs))]
		proto := strings.ToLower(fmt.Sprintf("%v", base["protocol"]))
		delete(base, "protocol")

		port := 0
		fmt.Sscanf(fmt.Sprintf("%v", base["port"]), "%d", &port)

		if !httpsPorts[port] {
			max--
			continue
		}
		host, _ := base["host"].(string)
		sni, _ := base["sni"].(string)
		if host == "" && sni == "" {
			max--
			continue
		}
		if host == "" {
			host = sni
		}

		ipIdx := weightedIndex(weights)
		cleanIP := ips[ipIdx]
		alpn := alpns[rand.Intn(len(alpns))]
		fp := fps[rand.Intn(len(fps))]
		idx++

		switch proto {
		case "vmess":
			net, _ := base["net"].(string)
			if net != "ws" && net != "grpc" {
				max--
				continue
			}
			base["host"] = host
			base["sni"] = host
			base["tls"] = "tls"
			base["add"] = cleanIP
			base["fp"] = fp
			base["alpn"] = alpn
			base["ps"] = fmt.Sprintf("%d-CF-%s-ws-%s-%s", idx, proto, fp, alpn)

			b, err := json.Marshal(base)
			if err == nil {
				out = append(out, "vmess://"+base64.StdEncoding.EncodeToString(b))
			}
			count--

		case "vless", "trojan":
			t, _ := base["type"].(string)
			if t != "ws" && t != "grpc" {
				max--
				continue
			}
			portStr := fmt.Sprintf("%v", base["port"])
			delete(base, "port")
			delete(base, "address")
			base["sni"] = host
			base["host"] = host
			base["tls"] = "tls"
			base["fp"] = fp
			base["alpn"] = alpn

			var id string
			if v, ok := base["uuid"].(string); ok {
				id = v
			} else if v, ok := base["password"].(string); ok {
				id = v
			}

			params := url.Values{}
			for k, v := range base {
				if k != "uuid" && k != "password" {
					params.Set(k, fmt.Sprintf("%v", v))
				}
			}
			name := fmt.Sprintf("%d-CF-%s-%s-%s-%s", idx, proto, t, fp, alpn)
			confStr := fmt.Sprintf("%s://%s@%s:%s?%s#%s",
				proto, id, cleanIP, portStr, params.Encode(), url.QueryEscape(name))
			out = append(out, confStr)
			count--
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

// extractVMessConfigs finds all vmess:// URIs in text and decodes them.
func extractVMessConfigs(text string) []map[string]interface{} {
	var out []map[string]interface{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "vmess://") {
			continue
		}
		b64 := line[len("vmess://"):]
		data, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			data, err = base64.RawStdEncoding.DecodeString(b64)
			if err != nil {
				continue
			}
		}
		var conf map[string]interface{}
		if err := json.Unmarshal(data, &conf); err != nil {
			continue
		}
		conf["protocol"] = "vmess"
		out = append(out, conf)
	}
	return out
}

// extractURLConfigs finds vless:// or trojan:// URIs and returns them as maps.
func extractURLConfigs(text string, proto string) []map[string]interface{} {
	var out []map[string]interface{}
	prefix := proto + "://"
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		u, err := url.Parse(line)
		if err != nil {
			continue
		}
		conf := map[string]interface{}{
			"protocol": proto,
			"address":  u.Hostname(),
			"port":     u.Port(),
		}
		if proto == "vless" {
			conf["uuid"] = u.User.Username()
		} else {
			conf["password"] = u.User.Username()
		}
		// Parse query params
		for k, v := range u.Query() {
			if len(v) > 0 {
				conf[k] = v[0]
			}
		}
		// Merge fragment as name
		if u.Fragment != "" {
			conf["name"] = u.Fragment
		}
		out = append(out, conf)
	}
	return out
}

// encodeVMess serialises a VMessConfig as a vmess:// URI.
func encodeVMess(conf VMessConfig) (string, error) {
	b, err := json.Marshal(conf)
	if err != nil {
		return "", err
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(b), nil
}

// newUUID generates a pseudo-random UUID v4.
func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// weightedIndex picks an index according to a probability weight slice.
func weightedIndex(weights []float64) int {
	r := rand.Float64()
	cum := 0.0
	for i, w := range weights {
		cum += w
		if r <= cum {
			return i
		}
	}
	return len(weights) - 1
}
