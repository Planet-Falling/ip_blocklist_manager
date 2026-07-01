import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Optional

from utils import fetch_url, merge_networks, save_networks, load_networks

logger = logging.getLogger("ip-blocklist")


class BaseSource(ABC):
    def __init__(self, name: str, config: dict[str, Any], data_dir: str):
        self.name = name
        self.config = config
        self.data_dir = data_dir
        self._last_update: float = 0
        self._networks: set[str] = set()
        self._cache_file: str = f"{data_dir}/{self.name.lower().replace(' ', '_')}.txt"

    @abstractmethod
    def fetch(self) -> set[str]:
        ...

    def fetch_with_retry(self, url: str, retries: int = 3, timeout: int = 60) -> str:
        return fetch_url(url, retries=retries, timeout=timeout)

    def download(self) -> Optional[set[str]]:
        try:
            self._networks = self.fetch()
            return self._networks
        except Exception as e:
            logger.error("Failed to download from %s: %s", self.name, e)
            return None

    def update(self) -> bool:
        try:
            networks = self.download()
            if networks is None:
                return False
            merged = set(merge_networks(networks))
            self._networks = merged
            save_networks(merged, self._cache_file)
            self._last_update = time.time()
            logger.info(
                "%s: downloaded %d entries, merged to %d networks",
                self.name,
                len(networks),
                len(merged),
            )
            return True
        except Exception as e:
            logger.error("%s update failed: %s", self.name, e)
            return False

    def load_cached(self) -> set[str]:
        self._networks = load_networks(self._cache_file)
        return self._networks

    def get_networks(self) -> set[str]:
        return self._networks

    @property
    def network_count(self) -> int:
        return len(self._networks)

    @property
    def last_update(self) -> float:
        return self._last_update
