#!/usr/bin/env bash
set -euo pipefail

# IP Blocklist Manager - Complete Cleanup Script
# 清空所有由 ip-blocklist-manager 创建的防火墙规则和缓存数据

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

if [ "$EUID" -ne 0 ]; then
    error "Please run as root (sudo)"
    exit 1
fi

echo "========================================"
echo "  IP Blocklist Manager - Cleanup"
echo "========================================"

# ---- 0. Environment check ----
DOCKER_RUNNING=false
if command -v docker &>/dev/null && docker ps --format '{{.ID}}' &>/dev/null 2>&1; then
    DOCKER_RUNNING=true
    warn "Docker is running on this system."
    warn "This script only removes blocklist_v4/blocklist_v6 sets and INPUT DROP rules."
    warn "Docker iptables/nftables rules will NOT be affected."
    echo ""
    read -r -p "Continue cleanup? [y/N] " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        info "Cleanup cancelled."
        exit 0
    fi
fi

IPTABLES_MODE=$(iptables --version 2>/dev/null || echo "unknown")
info "iptables mode: $IPTABLES_MODE"

# ---- 1. Clean nftables sets & rules ----
info "Cleaning nftables blocklist_v4/blocklist_v6 sets..."

for family in ip ip6; do
    for set_name in blocklist_v4 blocklist_v6; do
        # Remove the INPUT rule referencing the set
        handle=$(nft -a list chain "$family" filter INPUT 2>/dev/null | grep "@$set_name" | grep -o 'handle [0-9]*' | cut -d' ' -f2)
        if [ -n "$handle" ]; then
            info "  Deleting rule referencing $set_name in $family filter INPUT (handle $handle)"
            nft delete rule "$family" filter INPUT handle "$handle" 2>/dev/null || true
        fi
        # Delete the set
        if nft list set "$family" filter "$set_name" &>/dev/null; then
            info "  Deleting nftables set $family filter $set_name"
            nft delete set "$family" filter "$set_name" 2>/dev/null || warn "  Failed to delete set $set_name"
        fi
    done
done

# ---- 2. Clean iptables DROP rules in INPUT ----
info "Cleaning iptables DROP rules in INPUT..."
for cmd in iptables ip6tables; do
    $cmd -L INPUT -n --line-numbers 2>/dev/null | grep -E 'DROP\s+all\s+--\s+[0-9]' | awk '{print $1}' | sort -rn | while read num; do
        info "  Deleting rule $num from $cmd INPUT"
        $cmd -D INPUT "$num" 2>/dev/null || true
    done
done

# ---- 3. Clean data directory ----
DATA_DIR="${1:-/var/lib/ip-blocklist}"
if [ -d "$DATA_DIR" ]; then
    info "Cleaning data directory: $DATA_DIR"
    rm -rf "${DATA_DIR:?}/"*
    info "  All cached blocklist data removed"
else
    info "Data directory $DATA_DIR does not exist, skipping"
fi

echo "========================================"
info "Cleanup complete!"
echo ""
echo "Summary:"
echo "  - nftables blocklist_v4/blocklist_v6 sets removed"
echo "  - iptables DROP rules in INPUT cleaned"
echo "  - Cached data in $DATA_DIR cleared"
echo "========================================"
