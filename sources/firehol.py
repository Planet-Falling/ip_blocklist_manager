import logging

from sources.base import BaseSource
from utils import parse_netset

logger = logging.getLogger("ip-blocklist")


class FireHOLSource(BaseSource):
    def __init__(self, config: dict, data_dir: str):
        super().__init__("FireHOL", config, data_dir)
        self.levels = config.get("levels", [])

    def fetch(self) -> set[str]:
        networks: set[str] = set()
        errors: list[str] = []

        for level_cfg in self.levels:
            if not level_cfg.get("enabled", True):
                continue
            url = level_cfg.get("url")
            level_name = level_cfg.get("level", "unknown")
            if not url:
                continue
            try:
                text = self.fetch_with_retry(url)
                parsed = parse_netset(text)
                networks |= parsed
                logger.info("FireHOL Level %s: %d entries", level_name, len(parsed))
            except Exception as e:
                errors.append(f"Level {level_name}: {e}")

        if errors and not networks:
            raise RuntimeError(f"All FireHOL fetches failed: {'; '.join(errors)}")

        return networks
