import logging

from sources.base import BaseSource
from utils import parse_spamhaus_txt, parse_spamhaus_json

logger = logging.getLogger("ip-blocklist")


class SpamhausSource(BaseSource):
    def __init__(self, config: dict, data_dir: str):
        super().__init__("Spamhaus_DROP", config, data_dir)
        self.urls = config.get("urls", {})

    def fetch(self) -> set[str]:
        networks: set[str] = set()
        errors: list[str] = []

        # TXT format
        txt_url = self.urls.get("txt")
        if txt_url:
            try:
                text = self.fetch_with_retry(txt_url)
                networks |= parse_spamhaus_txt(text)
                logger.info("Spamhaus TXT: %d entries", len(networks))
            except Exception as e:
                errors.append(f"TXT: {e}")

        # JSON v4
        json_v4_url = self.urls.get("json_v4")
        if json_v4_url:
            try:
                text = self.fetch_with_retry(json_v4_url)
                networks |= parse_spamhaus_json(text)
                logger.info("Spamhaus JSONv4: %d entries", len(networks))
            except Exception as e:
                errors.append(f"JSONv4: {e}")

        # JSON v6
        json_v6_url = self.urls.get("json_v6")
        if json_v6_url:
            try:
                text = self.fetch_with_retry(json_v6_url)
                networks |= parse_spamhaus_json(text)
                logger.info("Spamhaus JSONv6: %d entries", len(networks))
            except Exception as e:
                errors.append(f"JSONv6: {e}")

        if errors and not networks:
            raise RuntimeError(f"All Spamhaus fetches failed: {'; '.join(errors)}")

        return networks
