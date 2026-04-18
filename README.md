# netmon — Network Traffic Monitor

A fast, zero-dependency network monitoring tool written in Rust with three modes:

| Mode | Command | What it does |
|---|---|---|
| **TUI** | `netmon tui` | Interactive full-screen terminal UI |
| **Log** | `netmon log` | Continuously appends formatted reports to a file |
| **Prometheus** | `netmon prometheus` | Serves `/metrics` for Prometheus scraping |

---

## Requirements

- Linux (reads `/proc/net/*`, `/proc/PID/*`)
- **Rust ≥ 1.80** — install via [rustup.rs](https://rustup.rs)
- Root or `CAP_NET_ADMIN` recommended (for full PID resolution across all processes)

---

## Build & Install

```bash
git clone <repo>
cd netmon
./build.sh                      # builds release binary
./build.sh /usr/local/bin/netmon   # build + copy to PATH
```

Or directly:
```bash
cargo build --release
./target/release/netmon --help
```

---

## Mode 1 — TUI

Interactive full-screen terminal UI with three tabs.

```bash
netmon tui                    # default: 1s refresh
netmon tui -i 500             # 500ms refresh
netmon tui --pid 1234         # filter to one PID
netmon tui --port 443         # filter to one port
netmon tui --listen           # show only LISTEN sockets
```

### Connections tab columns

| Column | Description |
|---|---|
| PID | Process ID owning the socket |
| PROCESS | Process short name |
| CMDLINE | Full command line (truncated, expand with Enter) |
| PROTO | TCP / TCP6 / UDP / UDP6 |
| LOCAL ADDR | Local IP address |
| L.PORT | Local port |
| REMOTE ADDR | Remote IP (- for unconnected) |
| R.PORT | Remote port |
| STATE | ESTABLISHED / LISTEN / TIME_WAIT / … |
| USER | Username resolved from UID |
| UID | Numeric user ID |
| INODE | Socket inode number |
| RX_Q | Receive queue depth (bytes) |
| TX_Q | Transmit queue depth (bytes) |

### Keyboard shortcuts

| Key | Action |
|---|---|
| `Tab` / `BackTab` | Switch tabs |
| `↑↓` / `j k` | Navigate rows |
| `PgUp` / `PgDn` | Page up/down |
| `g` / `G` | First / Last row |
| `Enter` | Full detail popup (PID, cmdline, exe, cwd, inode, queues) |
| `/` | Open filter input (live search) |
| `Esc` | Clear filter / close popup |
| `s` | Cycle sort column |
| `S` | Toggle sort direction |
| `p` | Pause / resume live updates |
| `r` | Force immediate refresh |
| `?` | Help popup |
| `q` / `Ctrl-C` | Quit |

---

## Mode 2 — Log

Continuously collect snapshots and **append** to a file. Each sample writes a
full formatted block including:

- Global connection summary  
- Per-interface stats with visual bar graphs  
- Per-process table with RX/TX bars + **full command line** (wrapped)  
- Full connection table with exe path and cmdline inline  

```bash
netmon log                         # → netmon.log, every 5s
netmon log -o /var/log/net.log     # custom path
netmon log -i 2000                 # every 2s
netmon log -o net.log -i 10000    # 10s interval
```

### Sample output

```
════════════════════════════════════════════════════════════════════════════════
 ◉ netmon  SAMPLE #1     │ 2025-04-18 09:12:00.123  │  interval: 5.0s
════════════════════════════════════════════════════════════════════════════════

 ┌─[ GLOBAL SUMMARY ]─────────────────────────────────────────────────────────
 │  total:  142  estab:   87  listen:  24  time_wait:   18  close_wait:  3  udp:  10
 │  RX:         1.24 MB/s   TX:       312.50 KB/s
 └───────────────────────────────────────────────────────────────────────────

 ┌─[ PROCESS TRAFFIC  active:12 ]─────────────────────────────────────────────
 │  PID      PROCESS                CONNS    CPU%        MEM          RX/s          TX/s
 │  ·········································································
 │  12345    nginx                      8    0.2%    48.00 MB      1.18 MB/s    89.12 KB/s
 │     RX [████████████████████░░░░░░░░░░░░░░░░░░░░]       1.18 MB/s
 │     TX [████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░]      89.12 KB/s
 │     cmdline: /usr/sbin/nginx -g daemon off;
```

---

## Mode 3 — Prometheus Exporter

Starts an HTTP server serving standard Prometheus text format on `/metrics`.

```bash
netmon prometheus                    # port 9090, 5s interval
netmon prometheus -p 9100            # custom port
netmon prometheus -p 9090 -i 10000  # 10s collection interval
```

### Endpoints

| Path | Description |
|---|---|
| `/metrics` | Prometheus metrics (text/plain; version=0.0.4) |
| `/health` | Returns `{"status":"ok"}` — use for liveness probes |
| `/` | HTML dashboard with metric reference |

### prometheus.yml

```yaml
scrape_configs:
  - job_name: netmon
    scrape_interval: 10s
    static_configs:
      - targets: ['localhost:9090']
```

### Full metric reference

```
# Connection counts
netmon_connections_total
netmon_connections_established
netmon_connections_listen
netmon_connections_time_wait
netmon_connections_close_wait
netmon_connections_syn_sent
netmon_connections_udp
netmon_connection_state_count{state="..."}
netmon_connection_protocol_count{protocol="..."}
netmon_listen_port{protocol="TCP",port="443"}

# Aggregate throughput
netmon_rx_bytes_per_second
netmon_tx_bytes_per_second

# Per-interface (label: interface="eth0")
netmon_interface_rx_bytes_total
netmon_interface_tx_bytes_total
netmon_interface_rx_packets_total
netmon_interface_tx_packets_total
netmon_interface_rx_errors_total
netmon_interface_tx_errors_total
netmon_interface_rx_bytes_per_second
netmon_interface_tx_bytes_per_second

# Per-process (labels: pid="1234",process="nginx")
netmon_process_connection_count
netmon_process_rx_bytes_total        # from /proc/PID/io read_bytes
netmon_process_tx_bytes_total        # from /proc/PID/io write_bytes
netmon_process_rx_bytes_per_second
netmon_process_tx_bytes_per_second
netmon_process_cpu_percent
netmon_process_memory_bytes
netmon_process_info{...,cmdline="..."}   # full cmdline as label, value=1

# Meta
netmon_scrape_count_total
netmon_collection_timestamp_ms
```

### Grafana

Import `grafana-dashboard.json` (included) — set data source to your
Prometheus instance. Panels include:

- Stat cards: total connections, established, RX/TX rates  
- Time-series: connection states, throughput, per-interface rates  
- Top-N processes: RX rate, TX rate, CPU%, memory  
- Breakdown tables: state distribution, protocol pie chart  

---

## Architecture

```
src/
├── main.rs          CLI entry point, signal handler, subcommand dispatch
├── types.rs         Shared data structures (Connection, Snapshot, …)
├── collector.rs     /proc/net/* + /proc/PID/* reader, builds Snapshot
├── tui.rs           ratatui interactive UI
├── logger.rs        File appender with formatted reports
└── prometheus.rs    HTTP server + Prometheus text format renderer
```

## Data sources

| Data | Source |
|---|---|
| TCP/UDP sockets | `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` |
| Socket → PID mapping | `/proc/PID/fd/*` (socket inodes) |
| Full command line | `/proc/PID/cmdline` |
| Executable path | `/proc/PID/exe` (symlink) |
| Working directory | `/proc/PID/cwd` (symlink) |
| Process I/O | `/proc/PID/io` (read_bytes / write_bytes) |
| Interface stats | sysinfo `Networks` (reads `/proc/net/dev`) |
| CPU / memory | sysinfo `System` (reads `/proc/stat`, `/proc/PID/status`) |
| Username | `/etc/passwd` |
