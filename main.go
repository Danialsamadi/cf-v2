package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"v2ray-cloudflare-gui/service"
)

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

type appState struct {
	svc        *service.Service
	validIPs   []service.IPResult
	cancelFn   context.CancelFunc
	scanning   bool
	alpns      []string
	useragents []string
}

func defaultState() *appState {
	return &appState{
		svc:   service.New(),
		alpns: []string{"h2", "http/1.1", "h2,http/1.1"},
		useragents: []string{
			"chrome", "firefox", "safari", "random",
			"randomized", "ios", "android", "edge",
		},
	}
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	a := app.New()
	a.Settings().SetTheme(theme.DarkTheme())
	w := a.NewWindow("V2Ray + Cloudflare  |  Clean IP Finder")
	w.Resize(fyne.NewSize(1000, 780))

	state := defaultState()
	w.SetContent(buildUI(w, state))
	w.ShowAndRun()
}

// ---------------------------------------------------------------------------
// UI builder — uses container.NewBorder as root so tabs fill the window
// ---------------------------------------------------------------------------

func buildUI(w fyne.Window, state *appState) fyne.CanvasObject {

	// ── Output entries (defined early so Start button can write to them) ──
	ipOutput := multiEntry("Clean IPs will appear here (sorted by latency)…")
	configOutput := multiEntry("Rewritten / Generated V2Ray configs will appear here…")
	workerOutput := multiEntry("Cloudflare Worker JS code will appear here…")

	// ── Tabs (results) — these fill all remaining vertical space ──────────
	tabs := container.NewAppTabs(
		container.NewTabItem("🌐  Clean IPs", ipOutput),
		container.NewTabItem("🔑  V2Ray Configs", configOutput),
		container.NewTabItem("⚙️  Worker Code", workerOutput),
	)
	tabs.SetTabLocation(container.TabLocationTop)

	// ── Copy / Save buttons ───────────────────────────────────────────────
	copyIPsBtn := widget.NewButton("📋 Copy IPs", func() {
		if strings.TrimSpace(ipOutput.Text) == "" {
			dialog.ShowInformation("Empty", "Run a scan first.", w)
			return
		}
		w.Clipboard().SetContent(ipOutput.Text)
		dialog.ShowInformation("✓", "IPs copied!", w)
	})
	copyConfigBtn := widget.NewButton("📋 Copy Configs", func() {
		if strings.TrimSpace(configOutput.Text) == "" {
			dialog.ShowInformation("Empty", "Run a scan first.", w)
			return
		}
		w.Clipboard().SetContent(configOutput.Text)
		dialog.ShowInformation("✓", "Configs copied!", w)
	})
	copyWorkerBtn := widget.NewButton("📋 Copy Worker", func() {
		if strings.TrimSpace(workerOutput.Text) == "" {
			dialog.ShowInformation("Empty", "Run a scan first.", w)
			return
		}
		w.Clipboard().SetContent(workerOutput.Text)
		dialog.ShowInformation("✓", "Worker code copied!", w)
	})
	saveBtn := widget.NewButton("💾 Save Files", func() {
		if len(state.validIPs) == 0 {
			dialog.ShowInformation("Empty", "Run a scan first.", w)
			return
		}
		saved := []string{}
		for name, text := range map[string]string{
			"clean_ips.txt": ipOutput.Text, "v2ray_configs.txt": configOutput.Text, "worker.js": workerOutput.Text,
		} {
			if strings.TrimSpace(text) == "" {
				continue
			}
			if err := os.WriteFile(name, []byte(text), 0644); err == nil {
				saved = append(saved, name)
			}
		}
		dialog.ShowInformation("Saved", "Saved:\n"+strings.Join(saved, "\n"), w)
	})

	// ── Progress / status ─────────────────────────────────────────────────
	progressBar := widget.NewProgressBar()
	progressBar.Hide()
	statusLabel := widget.NewLabel("Ready — configure settings below and press Start.")
	statusLabel.Wrapping = fyne.TextWrapWord

	// ── Toggle: Create Configs ────────────────────────────────────────────
	// Config paste area
	configPasteEntry := multiEntry("Paste your VMess / VLESS / Trojan configs here (ws+tls or grpc+tls)…\nvmess://eyJ2...\nvless://uuid@host:443?type=ws&security=tls&sni=host#Label")
	configPasteEntry.SetMinRowsVisible(4)

	vmLbl := widget.NewLabel("VMess: 0")
	vlLbl := widget.NewLabel("VLESS: 0")
	trLbl := widget.NewLabel("Trojan: 0")
	configPasteEntry.OnChanged = func(text string) {
		vm, vl, tr := service.CountParsedConfigs(text)
		vmLbl.SetText(fmt.Sprintf("VMess: %d", vm))
		vlLbl.SetText(fmt.Sprintf("VLESS: %d", vl))
		trLbl.SetText(fmt.Sprintf("Trojan: %d", tr))
	}

	configCountEntry := singleEntry("10", "How many configs to generate")

	// ALPN checkboxes
	alpnH2 := widget.NewCheck("h2", func(v bool) { state.alpns = toggleSlice(state.alpns, "h2", v) })
	alpnHTTP := widget.NewCheck("http/1.1", func(v bool) { state.alpns = toggleSlice(state.alpns, "http/1.1", v) })
	alpnBoth := widget.NewCheck("h2+http/1.1", func(v bool) { state.alpns = toggleSlice(state.alpns, "h2,http/1.1", v) })
	alpnH2.SetChecked(true)
	alpnHTTP.SetChecked(true)
	alpnBoth.SetChecked(true)

	// uTLS checkboxes
	allUAs := []string{"chrome", "firefox", "safari", "random", "randomized", "ios", "android", "edge"}
	uaChecks := make([]*widget.Check, len(allUAs))
	for i, ua := range allUAs {
		uaCopy := ua
		uaChecks[i] = widget.NewCheck(uaCopy, func(v bool) { state.useragents = toggleSlice(state.useragents, uaCopy, v) })
		uaChecks[i].SetChecked(true)
	}

	configPanel := container.NewVBox(
		widget.NewSeparator(),
		bLabel("Config Settings"),
		container.NewVBox(
			widget.NewLabel("Paste your existing ws/grpc+tls configs to rewrite with clean IPs.\nLeave empty to auto-generate fresh VMess configs."),
			configPasteEntry,
			container.NewHBox(vmLbl, widget.NewLabel("  "), vlLbl, widget.NewLabel("  "), trLbl),
		),
		container.NewBorder(nil, nil, bLabel("Output Count:"), nil, configCountEntry),
		widget.NewSeparator(),
		bLabel("ALPN  (Application-Layer Protocol Negotiation)"),
		container.NewHBox(alpnH2, alpnHTTP, alpnBoth),
		widget.NewSeparator(),
		bLabel("uTLS Fingerprint (Browser Simulation)"),
		container.NewGridWithColumns(4,
			uaChecks[0], uaChecks[1], uaChecks[2], uaChecks[3],
			uaChecks[4], uaChecks[5], uaChecks[6], uaChecks[7],
		),
	)
	configPanel.Hide()

	createConfigsCheck := widget.NewCheck("  ✏️  Rewrite / Generate Configs with Clean IPs", func(v bool) {
		if v {
			configPanel.Show()
		} else {
			configPanel.Hide()
		}
	})

	// ── Toggle: Generate Worker ───────────────────────────────────────────
	genWorkerCheck := widget.NewCheck("  ⚙️  Generate Cloudflare Worker Code", nil)
	genWorkerCheck.SetChecked(true)

	// ── IP Mode ───────────────────────────────────────────────────────────
	modeSelect := widget.NewSelect(
		[]string{"All Default IPs (Recommended)", "All IPs (Full Range)", "Custom Ranges"}, nil)
	modeSelect.SetSelected("All Default IPs (Recommended)")

	customCIDREntry := multiEntry("Enter custom CIDR ranges, one per line:\n104.16.0.0/13\n172.64.0.0/15")
	customCIDREntry.SetMinRowsVisible(3)
	customCIDREntry.Hide()

	ipCountLabel := bLabel("IP Count: –")
	refreshCount := func() {
		mode := resolveMode(modeSelect.Selected)
		ipCountLabel.SetText(fmt.Sprintf("IP Count: %s", commaInt(state.svc.TotalIPCount(mode, customCIDREntry.Text))))
	}
	refreshCount()
	modeSelect.OnChanged = func(s string) {
		if s == "Custom Ranges" {
			customCIDREntry.Show()
		} else {
			customCIDREntry.Hide()
		}
		refreshCount()
	}
	customCIDREntry.OnChanged = func(_ string) { refreshCount() }

	// ── Scan params ───────────────────────────────────────────────────────
	maxIPEntry := singleEntry("30", "Max clean IPs to find")
	pingEntry := singleEntry("3", "Ping count per IP")
	timeoutEntry := singleEntry("2000", "Timeout ms per ping")

	// ── Start / Stop ──────────────────────────────────────────────────────
	var startBtn *widget.Button
	startBtn = widget.NewButton("▶  Start Scan", func() {
		if state.scanning {
			if state.cancelFn != nil {
				state.cancelFn()
			}
			return
		}
		maxIP, _ := strconv.Atoi(strings.TrimSpace(maxIPEntry.Text))
		pings, _ := strconv.Atoi(strings.TrimSpace(pingEntry.Text))
		timeout, _ := strconv.Atoi(strings.TrimSpace(timeoutEntry.Text))
		if maxIP <= 0 {
			maxIP = 30
		}
		if pings <= 0 {
			pings = 3
		}
		if timeout <= 0 {
			timeout = 2000
		}

		cfg := service.ScanConfig{
			Mode: resolveMode(modeSelect.Selected), CustomCIDR: customCIDREntry.Text,
			MaxIPs: maxIP, PingCount: pings, TimeoutMs: timeout,
		}
		ctx, cancel := context.WithCancel(context.Background())
		state.cancelFn = cancel
		state.scanning = true
		state.validIPs = nil
		ipOutput.SetText("")
		configOutput.SetText("")
		workerOutput.SetText("")
		progressBar.SetValue(0)
		progressBar.Show()
		startBtn.SetText("⏹  Stop Scan")
		startBtn.Importance = widget.DangerImportance
		statusLabel.SetText("Scanning…")

		state.svc.Scan(ctx, cfg,
			func(p service.ScanProgress) {
				fyne.Do(func() {
					if maxIP > 0 {
						progressBar.SetValue(float64(p.Found) / float64(maxIP))
					}
					statusLabel.SetText(fmt.Sprintf("Testing %-15s | Found: %d / Tested: %d", p.CurrentIP, p.Found, p.Tested))
				})
			},
			func(results []service.IPResult, err error) {
				fyne.Do(func() {
					state.scanning = false
					state.validIPs = results
					state.cancelFn = nil
					startBtn.SetText("▶  Start Scan")
					startBtn.Importance = widget.HighImportance
					progressBar.SetValue(1)
					if err != nil {
						statusLabel.SetText("Error: " + err.Error())
						return
					}
					statusLabel.SetText(fmt.Sprintf("✅  Done! Found %d clean IPs.", len(results)))

					// ── IP tab ──
					ipOutput.SetText(state.svc.FormatIPList(results))

					// ── Config tab ──
					cfgCount := 10
					if n, e := strconv.Atoi(strings.TrimSpace(configCountEntry.Text)); e == nil && n > 0 {
						cfgCount = n
					}
					if createConfigsCheck.Checked {
						pasted := strings.TrimSpace(configPasteEntry.Text)
						if pasted != "" {
							lines := state.svc.RewriteConfigs(pasted, results, cfgCount, state.alpns, state.useragents)
							configOutput.SetText(strings.Join(lines, "\n"))
						} else {
							configOutput.SetText(strings.Join(state.svc.GenerateNewConfigs(results, cfgCount), "\n"))
						}
					} else {
						configOutput.SetText(state.svc.GenerateConfigs(results, cfgCount))
					}

					// ── Worker tab ──
					if genWorkerCheck.Checked {
						workerOutput.SetText(state.svc.GenerateWorkerCode(results))
					}
				})
			},
		)
	})
	startBtn.Importance = widget.HighImportance

	// ── Top panel (scrollable) ────────────────────────────────────────────
	toggleBox := container.NewVBox(
		createConfigsCheck,
		genWorkerCheck,
	)

	ipSettingsBox := container.NewVBox(
		widget.NewSeparator(),
		bLabel("─── IP Settings ───"),
		container.NewBorder(nil, nil, bLabel("Source:"), nil, modeSelect),
		customCIDREntry,
		container.NewGridWithColumns(3,
			vbox(bLabel("Max IPs"), maxIPEntry),
			vbox(bLabel("Ping Count"), pingEntry),
			vbox(bLabel("Timeout (ms)"), timeoutEntry),
		),
		ipCountLabel,
	)

	actionRow := container.NewHBox(startBtn, layout.NewSpacer(), copyIPsBtn, copyConfigBtn, copyWorkerBtn, saveBtn)

	progressBox := container.NewVBox(progressBar, statusLabel)

	// Title
	titleLabel := widget.NewLabelWithStyle("V2Ray + Cloudflare — Clean IP Finder",
		fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	subLabel := widget.NewLabelWithStyle("Scan Cloudflare IPs · Rewrite V2Ray configs · Generate Worker script",
		fyne.TextAlignCenter, fyne.TextStyle{Italic: true})

	// The top area is scrollable (settings, toggles, etc.)
	topScrollContent := container.NewVBox(
		titleLabel, subLabel,
		widget.NewSeparator(),
		toggleBox,
		configPanel,
		ipSettingsBox,
		widget.NewSeparator(),
		actionRow,
		progressBox,
		widget.NewSeparator(),
		bLabel("Results:"),
	)
	topScroll := container.NewVScroll(topScrollContent)
	topScroll.SetMinSize(fyne.NewSize(0, 360))

	// Results fill the bottom half
	resultsAndDonate := container.NewBorder(nil, nil, nil, nil, tabs)

	// Root: top (scrollable settings) | bottom (results tabs, fill space)
	root := container.NewVSplit(topScroll, resultsAndDonate)
	root.SetOffset(0.45) // ~45% top, 55% results

	return root
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func bLabel(text string) *widget.Label {
	l := widget.NewLabel(text)
	l.TextStyle = fyne.TextStyle{Bold: true}
	return l
}

func singleEntry(val, placeholder string) *widget.Entry {
	e := widget.NewEntry()
	e.SetText(val)
	e.SetPlaceHolder(placeholder)
	return e
}

func multiEntry(placeholder string) *widget.Entry {
	e := widget.NewMultiLineEntry()
	e.SetPlaceHolder(placeholder)
	e.Wrapping = fyne.TextWrapOff
	return e
}

func vbox(items ...fyne.CanvasObject) fyne.CanvasObject {
	return container.NewVBox(items...)
}

func resolveMode(s string) service.IPMode {
	switch s {
	case "All IPs (Full Range)":
		return service.ModeAllIPs
	case "Custom Ranges":
		return service.ModeCustom
	default:
		return service.ModeDefaultIPs
	}
}

func commaInt(n int) string {
	s := strconv.Itoa(n)
	out := ""
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out += ","
		}
		out += string(c)
	}
	return out
}

func toggleSlice(slice []string, item string, add bool) []string {
	for i, v := range slice {
		if v == item {
			if !add {
				return append(slice[:i], slice[i+1:]...)
			}
			return slice
		}
	}
	if add {
		return append(slice, item)
	}
	return slice
}
