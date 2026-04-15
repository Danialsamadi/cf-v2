# V2Ray + Cloudflare Clean IP Finder (Go GUI)

A cross-platform desktop GUI app written in **pure Go** using [Fyne](https://fyne.io).  
It replicates the functionality of [V2ray-Cloudflare](https://github.com/Nalbekink/V2ray-Cloudflare):

- Select Cloudflare IP source (Default / All / Custom CIDR ranges)
- Scan for clean IPs with configurable ping count & timeout
- Generate V2Ray VMess configs using the clean IPs
- Generate a Cloudflare Worker JS subscription script
- Copy or save all results

---

## Requirements

- **Go 1.21+** — <https://go.dev/dl/>
- **C compiler** (required by Fyne's OpenGL backend):
  - **macOS**: Xcode Command Line Tools (`xcode-select --install`)
  - **Linux**: `gcc`, `libgl1-mesa-dev`, `xorg-dev` (`sudo apt install build-essential libgl1-mesa-dev xorg-dev`)
  - **Windows**: [TDM-GCC](https://jmeubank.github.io/tdm-gcc/) or MSYS2

---

## Build & Run

```bash
# 1. Enter the project directory
cd v2ray-cloudflare-gui

# 2. Download dependencies
go mod tidy

# 3. Run directly
go run .

# 4. Build a standalone binary
go build -o v2ray-cloudflare-gui .

# macOS: package as .app
go install fyne.io/fyne/v2/cmd/fyne@latest
fyne package -os darwin -icon icon.png
```

---

## Usage

1. **IP Source** — choose from:
   - *All Default IPs (Recommended)*: curated ~150 CIDR ranges (faster scan)
   - *All IPs (Full Range)*: complete Cloudflare IP space (~61 k+ IPs)
   - *Custom Ranges*: paste your own CIDR list
2. **Max IPs** — stop after finding this many clean IPs (default 30)
3. **Ping Count** — how many HTTPS pings per candidate IP (default 3)
4. **Timeout** — per-ping timeout in ms (default 2000)
5. **Config Count** — how many V2Ray configs to generate (default 10)
6. Click **▶ Start Scan** — progress is shown live
7. Results appear in the **Clean IPs / V2Ray Configs / Worker Code** tabs
8. Use the **Copy** buttons or **Save All as Files** to export results

---

## Project Structure

```
v2ray-cloudflare-gui/
├── main.go              ← Fyne GUI only
├── go.mod / go.sum
├── service/
│   ├── service.go       ← high-level scan orchestrator
│   ├── ip.go            ← Cloudflare CIDR data + IP testing
│   ├── config.go        ← V2Ray config generation
│   ├── worker.go        ← Cloudflare Worker JS generation
│   └── types.go         ← shared types
└── README.md
```

---

## How It Works

### IP Testing
Each candidate IP is tested by sending `GET https://<ip>/` via HTTPS.  
A **network/TLS error** from the Cloudflare edge is treated as **success** (the edge responded).  
A **timeout** means the IP is unreachable.

### Config Generation
Valid IPs are weighted by latency (lower latency → higher probability) using a **softmin** distribution.  
VMess configs are generated with randomised ALPN and fingerprint fields.

### Worker Code
The produced `worker.js` file is a Cloudflare Worker script that acts as a V2Ray/Clash subscription endpoint, routing traffic through the clean IPs you found.

---

## License
MIT
