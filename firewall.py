import logging
import os
import subprocess
import sys
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger("ip-blocklist")

# nftables set names for the blocklist
SET_V4 = "blocklist_v4"
SET_V6 = "blocklist_v6"
NFT_TABLE = "filter"


class FirewallBackend(ABC):
    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def generate_apply_commands(self, v4_networks: list[str], v6_networks: list[str]) -> list[str]:
        ...

    @abstractmethod
    def generate_flush_commands(self) -> list[str]:
        ...

    @abstractmethod
    def show_stats(self) -> dict:
        ...

    def print_commands(self, cmds: list[str]) -> None:
        for cmd in cmds:
            print(f"    {cmd}")

    def execute_commands(self, cmds: list[str]) -> bool:
        for cmd in cmds:
            try:
                subprocess.run(cmd, shell=True, check=True, timeout=60)
            except Exception as e:
                logger.error("Command failed: %s (%s)", cmd, e)
                return False
        return True


class IptablesBackend(FirewallBackend):
    def __init__(self, config: dict):
        super().__init__(config)
        self._iptables = "iptables"
        self._ip6tables = "ip6tables"

    def generate_apply_commands(self, v4_networks: list[str], v6_networks: list[str]) -> list[str]:
        cmds = []
        for executable, networks in [(self._iptables, v4_networks), (self._ip6tables, v6_networks)]:
            if not networks:
                continue
            for net in networks:
                cmds.append(f"{executable} -A INPUT -s {net} -j DROP")
        return cmds

    def generate_flush_commands(self) -> list[str]:
        cmds = []
        for executable in [self._iptables, self._ip6tables]:
            cmds.append(f"echo 'Flush {executable} blocklist rules:'")
            cmds.append(f"{executable} -L INPUT -n --line-numbers 2>/dev/null | grep -E 'DROP\\s+all\\s+--\\s+[0-9]' | awk '{{print $1}}' | sort -rn | while read num; do {executable} -D INPUT $num 2>/dev/null; done || true")
        return cmds

    def show_stats(self) -> dict:
        stats = {}
        for label, cmd in [("v4", self._iptables), ("v6", self._ip6tables)]:
            try:
                result = subprocess.run(
                    [cmd, "-L", "INPUT", "-n", "-v"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    lines = result.stdout.strip().splitlines()
                    drop_rules = sum(1 for l in lines if "DROP" in l)
                    stats[label] = {"rules": drop_rules, "output": result.stdout}
            except (subprocess.TimeoutExpired, FileNotFoundError):
                stats[label] = {"rules": 0, "error": "unavailable"}
        return stats


class NftablesBackend(FirewallBackend):
    def __init__(self, config: dict):
        super().__init__(config)

    def generate_apply_commands(self, v4_networks: list[str], v6_networks: list[str]) -> list[str]:
        cmds = []
        for family, set_name, prefix, addr_type, networks in [
            ("ip", SET_V4, "ip", "ipv4_addr", v4_networks),
            ("ip6", SET_V6, "ip6", "ipv6_addr", v6_networks),
        ]:
            if not networks:
                continue
            cmds.append(f"nft add set {family} {NFT_TABLE} {set_name} {{ type {addr_type}\\; flags interval\\; auto-merge\\; }} 2>/dev/null || true")
            cmds.append(f"nft add rule {family} {NFT_TABLE} INPUT {prefix} saddr @{set_name} counter drop")
            cmds.append(f"nft flush set {family} {NFT_TABLE} {set_name} 2>/dev/null || true")
            for i in range(0, len(networks), 1000):
                chunk = networks[i:i + 1000]
                elements = ", ".join(chunk)
                cmds.append(f"nft add element {family} {NFT_TABLE} {set_name} {{ {elements} }}")
        return cmds

    def generate_flush_commands(self) -> list[str]:
        cmds = []
        for family, set_name in [("ip", SET_V4), ("ip6", SET_V6)]:
            cmds.append(f"handle=$(nft -a list chain {family} {NFT_TABLE} INPUT 2>/dev/null | grep '@{set_name}' | grep -o 'handle [0-9]*' | cut -d' ' -f2)")
            cmds.append(f"[ -n \"$handle\" ] && nft delete rule {family} {NFT_TABLE} INPUT handle $handle 2>/dev/null || true")
            cmds.append(f"nft delete set {family} {NFT_TABLE} {set_name} 2>/dev/null || true")
        return cmds

    def show_stats(self) -> dict:
        stats = {}
        for family, set_name in [("ip", SET_V4), ("ip6", SET_V6)]:
            try:
                result = subprocess.run(
                    ["nft", "list", "set", family, NFT_TABLE, set_name],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    elem_count = result.stdout.count("elements =") + result.stdout.count(",")
                    stats[family] = {"rules": elem_count, "output": result.stdout}
            except Exception:
                stats[family] = {"rules": 0, "error": "unavailable"}
        return stats


def get_firewall_backend(config: dict) -> Optional[FirewallBackend]:
    backend = config.get("backend", "nftables")
    if backend == "iptables":
        return IptablesBackend(config)
    elif backend == "nftables":
        return NftablesBackend(config)
    elif backend == "none":
        logger.info("Firewall backend disabled")
        return None
    else:
        logger.warning("Unknown backend '%s', falling back to nftables", backend)
        return NftablesBackend(config)


def detect_docker() -> bool:
    if not os.path.exists("/var/run/docker.sock"):
        return False
    try:
        r = subprocess.run(
            ["docker", "ps", "--format", "{{.ID}}"],
            capture_output=True, timeout=5,
        )
        if r.returncode == 0:
            return True
        stderr = (r.stderr or b"").decode("utf-8", errors="replace").lower()
        if r.returncode == 1 and "permission denied" in stderr:
            return True
        return False
    except FileNotFoundError:
        return False
    except subprocess.TimeoutExpired:
        return os.path.exists("/var/run/docker.sock")


def detect_iptables_mode() -> str:
    try:
        r = subprocess.run(
            ["iptables", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        if "nf_tables" in r.stdout:
            return "nft"
        elif "legacy" in r.stdout:
            return "legacy"
        return "unknown"
    except FileNotFoundError:
        return "not_found"


def check_env() -> dict:
    docker_running = detect_docker()
    iptables_mode = detect_iptables_mode()

    info = {
        "docker_running": docker_running,
        "iptables_mode": iptables_mode,
    }

    logger.debug("Environment: docker=%s, iptables=%s", docker_running, iptables_mode)

    if docker_running and iptables_mode == "legacy":
        info["warning"] = (
            "Docker is running but iptables is in legacy mode.\n"
            "  Blocklist rules via iptables-legacy may conflict with Docker.\n"
            "  Recommend using nftables backend (the default)."
        )
        info["suggest_backend"] = "nftables"
    else:
        info["warning"] = None
        info["suggest_backend"] = None

    return info


def prompt_backend(config: dict, env_info: dict) -> str:
    current = config.get("firewall", {}).get("backend", "nftables")

    if env_info["warning"]:
        print(f"\n{'!' * 60}")
        print(f"  ⚠  Environment Warning")
        print(f"{'!' * 60}")
        print(f"  {env_info['warning']}")
        print(f"  Current backend: {current}")
        print(f"  Suggested backend: nftables")
        print(f"{'!' * 60}")

    print(f"\n  Available backends:")
    print(f"    1) nftables  (use nft sets, safe with Docker)")
    print(f"    2) iptables  (use iptables INPUT DROP rules)")
    print(f"    3) none      (skip firewall rules)")

    choice = input(f"\n  Choose backend [1-3] (default: {current}): ").strip()
    if choice == "1":
        return "nftables"
    elif choice == "2":
        if env_info["docker_running"]:
            print("  ⚠  Warning: iptables backend with Docker may cause conflicts!")
            confirm = input("  Continue with iptables? [y/N] ").strip().lower()
            if confirm != "y":
                print("  Falling back to nftables")
                return "nftables"
        return "iptables"
    elif choice == "3":
        return "none"
    return current
