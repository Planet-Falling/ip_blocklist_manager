import ipaddress
import json
import logging
import re
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from pathlib import Path
from typing import Optional

logger = logging.getLogger("ip-blocklist")


IPV4_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"
)
IPV6_RE = re.compile(
    r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(/\d{1,3})?$"
)


def normalize_ip(entry: str) -> Optional[str]:
    entry = entry.strip()
    if not entry or entry.startswith("#") or entry.startswith(";"):
        return None
    entry = entry.split("#")[0].split(";")[0].strip()
    if not entry:
        return None
    try:
        if "/" in entry:
            net = ipaddress.ip_network(entry, strict=False)
            return str(net)
        else:
            ip = ipaddress.ip_address(entry)
            return str(ip) + ("/32" if ip.version == 4 else "/128")
    except ValueError:
        return None


def parse_cidr_range(line: str) -> Optional[str]:
    parts = line.split()
    if len(parts) < 2:
        return None
    try:
        start = ipaddress.IPv4Address(parts[0].strip())
        end = ipaddress.IPv4Address(parts[1].strip())
    except (ipaddress.AddressValueError, IndexError):
        return None
    networks = list(ipaddress.summarize_address_range(start, end))
    return ",".join(str(n) for n in networks)


def is_ipv4(s: str) -> bool:
    return bool(IPV4_RE.match(s))


def is_ipv6(s: str) -> bool:
    return bool(IPV6_RE.match(s))


def fetch_url(url: str, retries: int = 3, timeout: int = 60) -> str:
    last_exc = None
    for attempt in range(retries):
        try:
            t0 = time.perf_counter()
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "IP-Blocklist-Manager/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read().decode("utf-8", errors="replace")
            elapsed = time.perf_counter() - t0
            logger.info("Fetched %s in %.2fs (attempt %d/%d)", url, elapsed, attempt + 1, retries)
            return data
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
            last_exc = e
            logger.warning("Fetch %s failed (attempt %d/%d): %s", url, attempt + 1, retries, e)
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
    raise RuntimeError(f"Failed to fetch {url} after {retries} retries") from last_exc


def parse_spamhaus_txt(text: str) -> set[str]:
    networks: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";") or ";" not in line:
            continue
        parts = line.split(";")
        cidr = parts[0].strip()
        normalized = normalize_ip(cidr)
        if normalized:
            networks.add(normalized)
    return networks


def parse_spamhaus_json(text: str) -> set[str]:
    data = json.loads(text)
    networks: set[str] = set()
    for entry in data:
        cidr = entry.get("cidr", entry.get("prefix", ""))
        normalized = normalize_ip(cidr)
        if normalized:
            networks.add(normalized)
    return networks


def parse_netset(text: str) -> set[str]:
    networks: set[str] = set()
    for line in text.splitlines():
        normalized = normalize_ip(line)
        if normalized:
            networks.add(normalized)
    return networks


def parse_plain_ip_list(text: str) -> set[str]:
    networks: set[str] = set()
    for line in text.splitlines():
        normalized = normalize_ip(line)
        if normalized:
            networks.add(normalized)
    return networks


def parse_dshield_block(text: str) -> set[str]:
    networks: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ranges = parse_cidr_range(line)
        if ranges:
            for cidr in ranges.split(","):
                networks.add(cidr)
        else:
            normalized = normalize_ip(line)
            if normalized:
                networks.add(normalized)
    return networks


def merge_networks(networks: Iterable[str]) -> list[str]:
    v4_nets: list[ipaddress.IPv4Network] = []
    v6_nets: list[ipaddress.IPv6Network] = []
    for n in networks:
        try:
            net = ipaddress.ip_network(n, strict=False)
            if net.version == 4:
                v4_nets.append(net)
            else:
                v6_nets.append(net)
        except ValueError:
            continue
    merged_v4 = list(ipaddress.collapse_addresses(v4_nets))
    merged_v6 = list(ipaddress.collapse_addresses(v6_nets))
    result = [str(n) for n in merged_v4] + [str(n) for n in merged_v6]
    result.sort()
    return result


def save_networks(networks: Iterable[str], filepath: str) -> None:
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for net in networks:
            f.write(net + "\n")
    logger.info("Saved %d networks to %s", len(networks), filepath)


def load_networks(filepath: str) -> set[str]:
    path = Path(filepath)
    if not path.exists():
        return set()
    with open(path) as f:
        return {line.strip() for line in f if line.strip()}
