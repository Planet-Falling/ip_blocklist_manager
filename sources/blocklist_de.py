import logging

from sources.base import BaseSource
from utils import parse_plain_ip_list

logger = logging.getLogger("ip-blocklist")


class BlocklistDeSource(BaseSource):
    def __init__(self, config: dict, data_dir: str):
        super().__init__("Blocklist_de", config, data_dir)
        self.categories = config.get("categories", {})
        self.enabled_categories = config.get("enabled_categories", ["all"])

    def fetch(self) -> set[str]:
        networks: set[str] = set()
        errors: list[str] = []

        categories_to_fetch = self.enabled_categories
        if "*" in categories_to_fetch or "all" in categories_to_fetch:
            categories_to_fetch = list(self.categories.keys())

        for cat in categories_to_fetch:
            url = self.categories.get(cat)
            if not url:
                continue
            try:
                text = self.fetch_with_retry(url)
                parsed = parse_plain_ip_list(text)
                networks |= parsed
                logger.info("Blocklist.de %s: %d entries", cat, len(parsed))
            except Exception as e:
                errors.append(f"{cat}: {e}")

        if errors and not networks:
            raise RuntimeError(f"All Blocklist.de fetches failed: {'; '.join(errors)}")

        return networks
