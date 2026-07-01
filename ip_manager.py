import ipaddress
import logging
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Optional

from utils import merge_networks, save_networks, load_networks

logger = logging.getLogger("ip-blocklist")


class IPManager:
    def __init__(self, data_dir: str, max_memory_entries: int = 1_000_000):
        self.data_dir = data_dir
        self.max_memory_entries = max_memory_entries
        self._networks_v4: set[str] = set()
        self._networks_v6: set[str] = set()
        self._merged_cache: Optional[list[str]] = None
        self._merged_file = f"{data_dir}/merged_blocklist.txt"
        self._stats_file = f"{data_dir}/stats.json"

    @property
    def count_v4(self) -> int:
        return len(self._networks_v4)

    @property
    def count_v6(self) -> int:
        return len(self._networks_v6)

    @property
    def total_count(self) -> int:
        return self.count_v4 + self.count_v6

    def add_networks(self, networks: Iterable[str]) -> None:
        for net in networks:
            try:
                ipn = ipaddress.ip_network(net, strict=False)
                if ipn.version == 4:
                    self._networks_v4.add(str(ipn))
                else:
                    self._networks_v6.add(str(ipn))
            except ValueError:
                continue
        self._merged_cache = None

    def add_source_networks(self, source_name: str, networks: set[str]) -> None:
        before = self.total_count
        self.add_networks(networks)
        added = self.total_count - before
        logger.info("Added %d networks from %s (total: %d)", added, source_name, self.total_count)

    def merge(self) -> list[str]:
        if self._merged_cache is not None:
            return self._merged_cache
        all_nets: set[str] = self._networks_v4 | self._networks_v6
        self._merged_cache = merge_networks(all_nets)
        return self._merged_cache

    def save_merged(self) -> str:
        merged = self.merge()
        save_networks(merged, self._merged_file)
        logger.info("Saved merged blocklist: %d networks to %s", len(merged), self._merged_file)
        return self._merged_file

    def load_merged(self) -> list[str]:
        networks = load_networks(self._merged_file)
        self._reset()
        for net in networks:
            try:
                ipn = ipaddress.ip_network(net, strict=False)
                if ipn.version == 4:
                    self._networks_v4.add(net)
                else:
                    self._networks_v6.add(net)
            except ValueError:
                continue
        self._merged_cache = None
        logger.info("Loaded %d merged networks from cache", self.total_count)
        return list(networks)

    def get_v4_networks(self) -> list[str]:
        return sorted(self._networks_v4)

    def get_v6_networks(self) -> list[str]:
        return sorted(self._networks_v6)

    def clear(self) -> None:
        self._networks_v4.clear()
        self._networks_v6.clear()
        self._merged_cache = None
        logger.info("IPManager cleared")

    def _reset(self) -> None:
        self._networks_v4.clear()
        self._networks_v6.clear()
        self._merged_cache = None
