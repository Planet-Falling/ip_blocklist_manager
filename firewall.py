import logging
import subprocess
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger("ip-blocklist")


class FirewallBackend(ABC):
    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def apply_rules(self, v4_networks: list[str], v6_networks: list[str]) -> bool:
        ...

    @abstractmethod
    def flush_rules(self) -> bool:
        ...

    @abstractmethod
    def show_stats(self) -> dict:
        ...


class IptablesBackend(FirewallBackend):
    def __init__(self, config: dict):
        super().__init__(config)
        self.chain_v4 = config.get("chain_v4", "BLOCKLIST_V4")
        self.chain_v6 = config.get("chain_v6", "BLOCKLIST_V6")
        self._iptables = "iptables"
        self._ip6tables = "ip6tables"

    def _chain_exists(self, cmd: str, chain: str) -> bool:
        try:
            result = subprocess.run(
                [cmd, "-L", chain, "-n"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _create_chain(self, cmd: str, chain: str) -> bool:
        try:
            subprocess.run(
                [cmd, "-N", chain],
                check=True,
                capture_output=True,
                timeout=10,
            )
            return True
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            logger.error("Failed to create chain %s: %s", chain, e)
            return False

    def _flush_chain(self, cmd: str, chain: str) -> bool:
        try:
            subprocess.run(
                [cmd, "-F", chain],
                check=True,
                capture_output=True,
                timeout=30,
            )
            return True
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            logger.error("Failed to flush chain %s: %s", chain, e)
            return False

    def _add_rules(self, cmd: str, chain: str, networks: list[str]) -> int:
        added = 0
        for net in networks:
            try:
                subprocess.run(
                    [cmd, "-A", chain, "-s", net, "-j", "DROP"],
                    check=True,
                    capture_output=True,
                    timeout=5,
                )
                added += 1
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
                logger.warning("Failed to add rule for %s: %s", net, e)
        return added

    def _ensure_input_rule(self, cmd: str, chain: str) -> bool:
        try:
            result = subprocess.run(
                [cmd, "-C", "INPUT", "-j", chain],
                capture_output=True,
                timeout=5,
            )
            if result.returncode != 0:
                subprocess.run(
                    [cmd, "-I", "INPUT", "-j", chain],
                    check=True,
                    capture_output=True,
                    timeout=5,
                )
            return True
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            logger.error("Failed to ensure INPUT rule for %s: %s", chain, e)
            return False

    def apply_rules(self, v4_networks: list[str], v6_networks: list[str]) -> bool:
        success = True

        for cmd, chain, networks in [
            (self._iptables, self.chain_v4, v4_networks),
            (self._ip6tables, self.chain_v6, v6_networks),
        ]:
            if not networks:
                continue

            if not self._chain_exists(cmd, chain):
                if not self._create_chain(cmd, chain):
                    success = False
                    continue

            self._flush_chain(cmd, chain)

            added = self._add_rules(cmd, chain, networks)
            logger.info("Added %d/%d rules to %s", added, len(networks), chain)

            self._ensure_input_rule(cmd, chain)

        return success

    def flush_rules(self) -> bool:
        success = True
        for cmd, chain in [
            (self._iptables, self.chain_v4),
            (self._ip6tables, self.chain_v6),
        ]:
            if self._chain_exists(cmd, chain):
                self._flush_chain(cmd, chain)
                try:
                    subprocess.run(
                        [cmd, "-D", "INPUT", "-j", chain],
                        check=True,
                        capture_output=True,
                        timeout=5,
                    )
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                    pass
                try:
                    subprocess.run(
                        [cmd, "-X", chain],
                        check=True,
                        capture_output=True,
                        timeout=10,
                    )
                    logger.info("Deleted chain %s", chain)
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
                    logger.warning("Failed to delete chain %s: %s", chain, e)
                    success = False
        return success

    def show_stats(self) -> dict:
        stats = {}
        for label, cmd, chain in [
            ("v4", self._iptables, self.chain_v4),
            ("v6", self._ip6tables, self.chain_v6),
        ]:
            try:
                result = subprocess.run(
                    [cmd, "-L", chain, "-n", "-v"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    lines = result.stdout.strip().splitlines()
                    rule_count = max(0, len(lines) - 2)
                    stats[label] = {"rules": rule_count, "output": result.stdout}
            except (subprocess.TimeoutExpired, FileNotFoundError):
                stats[label] = {"rules": 0, "error": "unavailable"}
        return stats


class NftablesBackend(FirewallBackend):
    def __init__(self, config: dict):
        super().__init__(config)
        self.chain_v4 = config.get("chain_v4", "BLOCKLIST_V4")
        self.chain_v6 = config.get("chain_v6", "BLOCKLIST_V6")
        self.table = config.get("table", "filter")
        self._nft = "nft"

    def _nft_cmd(self, args: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            [self._nft] + args,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def _ensure_table_chain(self, family: str, chain: str) -> bool:
        result = self._nft_cmd(["list", "chain", family, self.table, chain])
        if result.returncode == 0:
            return True

        result = self._nft_cmd(["list", "table", family, self.table])
        if result.returncode != 0:
            r = self._nft_cmd(["add", "table", family, self.table])
            if r.returncode != 0:
                logger.error("Failed to create nftables table: %s", r.stderr)
                return False

        r = self._nft_cmd([
            "add", "chain", family, self.table, chain,
            "{ type filter hook input priority 0; policy accept; }",
        ])
        if r.returncode != 0:
            logger.error("Failed to create chain %s: %s", chain, r.stderr)
            return False
        return True

    def apply_rules(self, v4_networks: list[str], v6_networks: list[str]) -> bool:
        success = True

        for family, chain, networks in [
            ("ip", self.chain_v4, v4_networks),
            ("ip6", self.chain_v6, v6_networks),
        ]:
            if not networks:
                continue
            if not self._ensure_table_chain(family, chain):
                success = False
                continue

            self._nft_cmd(["flush", "chain", family, self.table, chain])

            added = 0
            batch_size = 100
            for i in range(0, len(networks), batch_size):
                batch = networks[i:i + batch_size]
                rule = "add rule {} {} {} drop".format(family, self.table, chain)
                ruleset = "; ".join(
                    f"{rule} ip saddr {net}" if family == "ip"
                    else f"{rule} ip6 saddr {net}"
                    for net in batch
                )
                if family == "ip":
                    elements = ", ".join(batch)
                    r = self._nft_cmd([
                        "add", "rule", family, self.table, chain,
                        "ip", "saddr", "{" + elements + "}", "drop",
                    ])
                else:
                    elements = ", ".join(batch)
                    r = self._nft_cmd([
                        "add", "rule", family, self.table, chain,
                        "ip6", "saddr", "{" + elements + "}", "drop",
                    ])
                if r.returncode == 0:
                    added += len(batch)
                else:
                    for net in batch:
                        r2 = self._nft_cmd([
                            "add", "rule", family, self.table, chain,
                            "ip", "saddr", net, "drop",
                        ] if family == "ip" else [
                            "add", "rule", family, self.table, chain,
                            "ip6", "saddr", net, "drop",
                        ])
                        if r2.returncode == 0:
                            added += 1

            logger.info("Added %d/%d rules to nftables %s %s", added, len(networks), family, chain)

        return success

    def flush_rules(self) -> bool:
        success = True
        for family, chain in [
            ("ip", self.chain_v4),
            ("ip6", self.chain_v6),
        ]:
            r = self._nft_cmd(["flush", "chain", family, self.table, chain])
            if r.returncode != 0:
                logger.warning("Failed to flush %s %s: %s", family, chain, r.stderr)
                success = False
        return success

    def show_stats(self) -> dict:
        stats = {}
        for family, chain in [
            ("ip", self.chain_v4),
            ("ip6", self.chain_v6),
        ]:
            try:
                result = self._nft_cmd(["list", "chain", family, self.table, chain])
                if result.returncode == 0:
                    rule_count = result.stdout.strip().count("drop")
                    stats[family] = {"rules": rule_count, "output": result.stdout}
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
