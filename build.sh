#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────
#  netmon build script
#  Requires: Rust >= 1.80  (rustup.rs)
# ─────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'; NC='\033[0m'

info()  { echo -e "${CYN}[netmon]${NC} $*"; }
ok()    { echo -e "${GRN}[  OK  ]${NC} $*"; }
warn()  { echo -e "${YLW}[ WARN ]${NC} $*"; }
die()   { echo -e "${RED}[ FAIL ]${NC} $*"; exit 1; }

# ── Check Rust ───────────────────────────────────────────
if ! command -v cargo &>/dev/null; then
    die "cargo not found. Install Rust: https://rustup.rs"
fi

RUST_VER=$(rustc --version | awk '{print $2}')
RUST_MAJOR=$(echo "$RUST_VER" | cut -d. -f1)
RUST_MINOR=$(echo "$RUST_VER" | cut -d. -f2)
info "Rust $RUST_VER detected"

if [[ "$RUST_MAJOR" -lt 1 ]] || [[ "$RUST_MAJOR" -eq 1 && "$RUST_MINOR" -lt 80 ]]; then
    warn "Rust >= 1.80 recommended. You have $RUST_VER"
    warn "Run: rustup update stable"
fi

# ── Build ────────────────────────────────────────────────
info "Building netmon (release)…"
cargo build --release 2>&1 | grep -E "^(error|warning\[|   Compiling|    Finished)" || true
cargo build --release

BINARY="./target/release/netmon"
[[ -f "$BINARY" ]] || die "Build failed — binary not found"
ok "Built: $BINARY ($(du -sh "$BINARY" | cut -f1))"

# ── Optional install ─────────────────────────────────────
DEST="${1:-}"
if [[ -n "$DEST" ]]; then
    cp "$BINARY" "$DEST"
    ok "Installed to $DEST"
elif command -v install &>/dev/null && [[ -w /usr/local/bin ]]; then
    read -rp "Install to /usr/local/bin/netmon? [y/N] " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        install -m755 "$BINARY" /usr/local/bin/netmon
        ok "Installed to /usr/local/bin/netmon"
    fi
fi

echo ""
echo -e "${CYN}Usage:${NC}"
echo "  $BINARY tui                          # interactive TUI"
echo "  $BINARY tui -i 500                   # 500ms refresh"
echo "  $BINARY tui --pid 1234               # filter to PID"
echo "  $BINARY tui --port 443               # filter to port"
echo "  $BINARY log -o /var/log/netmon.log   # log to file (5s interval)"
echo "  $BINARY log -o net.log -i 2000       # log every 2s"
echo "  $BINARY prometheus                   # serve :9090/metrics"
echo "  $BINARY prometheus -p 9100 -i 10000  # custom port & interval"
