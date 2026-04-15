// Package service provides a high-level API for scanning Cloudflare IPs,
// generating V2Ray configurations, and producing Cloudflare Worker scripts.
package service

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// ScanProgress is a snapshot of a running scan's state.
type ScanProgress struct {
	Tested    int
	Found     int
	Total     int
	CurrentIP string
}

// Service is the central object that orchestrates scanning and code generation.
type Service struct {
	mu sync.Mutex
}

// New creates and returns a new Service.
func New() *Service {
	return &Service{}
}

// TotalIPCount returns how many IPs are in the selected mode's CIDR pool.
func (s *Service) TotalIPCount(mode IPMode, customCIDR string) int {
	cidrs := GetCIDRs(mode, customCIDR)
	return TotalIPCount(cidrs)
}

// Scan starts an IP scan in the background.
// progressFn is called from background goroutines (use fyne.Do in the callback).
// doneFn is called once when the scan finishes or is cancelled.
func (s *Service) Scan(
	ctx context.Context,
	cfg ScanConfig,
	progressFn func(ScanProgress),
	doneFn func([]IPResult, error),
) {
	cidrs := GetCIDRs(cfg.Mode, cfg.CustomCIDR)
	if len(cidrs) == 0 {
		doneFn(nil, fmt.Errorf("no IP ranges available for the selected mode"))
		return
	}

	go func() {
		weights := CIDRWeights(cidrs)
		var validIPs []IPResult
		var mu sync.Mutex
		tested := 0
		total := TotalIPCount(cidrs)

		const maxConcurrent = 20
		sem := make(chan struct{}, maxConcurrent)
		var wg sync.WaitGroup

		for {
			select {
			case <-ctx.Done():
				wg.Wait()
				mu.Lock()
				result := make([]IPResult, len(validIPs))
				copy(result, validIPs)
				mu.Unlock()
				doneFn(result, nil)
				return
			default:
			}

			mu.Lock()
			found := len(validIPs)
			mu.Unlock()

			if found >= cfg.MaxIPs {
				break
			}
			if tested >= total && total > 0 {
				break
			}

			ip, err := SampleWeightedIP(cidrs, weights)
			if err != nil {
				continue
			}

			wg.Add(1)
			sem <- struct{}{}

			go func(candidateIP string) {
				defer wg.Done()
				defer func() { <-sem }()

				result := TestIP(candidateIP, cfg.TimeoutMs, cfg.PingCount)

				mu.Lock()
				tested++
				if result != nil {
					validIPs = append(validIPs, *result)
				}
				t := tested
				f := len(validIPs)
				mu.Unlock()

				if progressFn != nil {
					progressFn(ScanProgress{
						Tested:    t,
						Found:     f,
						Total:     total,
						CurrentIP: candidateIP,
					})
				}
			}(ip)
		}

		wg.Wait()
		mu.Lock()
		result := make([]IPResult, len(validIPs))
		copy(result, validIPs)
		mu.Unlock()
		doneFn(result, nil)
	}()
}

// ── Config generation ─────────────────────────────────────────────────────

// GenerateConfigs creates default fresh VMess configs from clean IPs.
// Returns a newline-joined string of vmess:// URIs.
func (s *Service) GenerateConfigs(cleanIPs []IPResult, count int) string {
	configs := GenerateDefaultVMessConfigs(cleanIPs, count)
	return strings.Join(configs, "\n")
}

// GenerateNewConfigs returns a slice of fresh VMess configs (used when the
// user hasn't pasted their own configs but still wants output).
func (s *Service) GenerateNewConfigs(cleanIPs []IPResult, count int) []string {
	return GenerateDefaultVMessConfigs(cleanIPs, count)
}

// RewriteConfigs rewrites user-pasted VMess/VLESS/Trojan configs with clean IPs.
// alpns and fps control which ALPN and fingerprint values are picked.
func (s *Service) RewriteConfigs(
	rawConfigs string,
	cleanIPs []IPResult,
	count int,
	alpns []string,
	fps []string,
) []string {
	return ChangeConfigs(rawConfigs, cleanIPs, count, alpns, fps)
}

// CountParsedConfigs parses rawText and returns the count of VMess, VLESS,
// and Trojan configs found.  Used for the live badge display in the UI.
func CountParsedConfigs(rawText string) (vmess, vless, trojan int) {
	vm := extractVMessConfigs(rawText)
	vl := extractURLConfigs(rawText, "vless")
	tr := extractURLConfigs(rawText, "trojan")
	return len(vm), len(vl), len(tr)
}

// ── Worker code ───────────────────────────────────────────────────────────

// GenerateWorkerCode returns the Cloudflare Worker JS script using clean IPs.
func (s *Service) GenerateWorkerCode(cleanIPs []IPResult) string {
	return GenerateWorkerCode(cleanIPs)
}

// ── IP list formatting ────────────────────────────────────────────────────

// FormatIPList returns clean IPs sorted by latency as a human-readable string.
func (s *Service) FormatIPList(ips []IPResult) string {
	sorted := make([]IPResult, len(ips))
	copy(sorted, ips)
	// Simple insertion sort (lists are small)
	for i := 1; i < len(sorted); i++ {
		key := sorted[i]
		j := i - 1
		for j >= 0 && sorted[j].Latency > key.Latency {
			sorted[j+1] = sorted[j]
			j--
		}
		sorted[j+1] = key
	}

	var sb strings.Builder
	for _, r := range sorted {
		sb.WriteString(fmt.Sprintf("%s  (%d ms)\n", r.IP, r.Latency))
	}
	return sb.String()
}
