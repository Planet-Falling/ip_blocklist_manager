import logging

from sources.base import BaseSource
from utils import parse_dshield_block

logger = logging.getLogger("ip-blocklist")


class DShieldSource(BaseSource):
    def __init__(self, config: dict, data_dir: str):
        super().__init__("DShield", config, data_dir)
        self.url = config.get("url")

    def fetch(self) -> set[str]:
        if not self.url:
            return set()

        text = self.fetch_with_retry(self.url)
        networks = parse_dshield_block(text)
        logger.info("DShield: %d entries", len(networks))
        return networks
