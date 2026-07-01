#!/usr/bin/env python3
"""读取指定文件内的 IP 进行封禁，一行一个 IP，支持 # 注释。"""

import argparse
import ipaddress
import logging
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger("ban-ip-file")


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def normalize_ip(entry: str) -> str | None:
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
        ip = ipaddress.ip_address(entry)
        return str(ip) + ("/32" if ip.version == 4 else "/128")
    except ValueError:
        return None


def gen_nft_cmds(v4: list[str], v6: list[str]) -> list[str]:
    cmds = []
    for family, sname, prefix, addr_type, nets in [
        ("ip",  "blocklist_v4", "ip",  "ipv4_addr", v4),
        ("ip6", "blocklist_v6", "ip6", "ipv6_addr", v6),
    ]:
        if not nets:
            continue
        cmds.append(
            f"nft add set {family} filter {sname} "
            f"{{ type {addr_type}\\; flags interval\\; auto-merge\\; }} "
            f"2>/dev/null || true"
        )
        cmds.append(
            f"nft add rule {family} filter INPUT {prefix} saddr @{sname} "
            f"counter drop 2>/dev/null || true"
        )
        for i in range(0, len(nets), 1000):
            chunk = nets[i:i + 1000]
            cmds.append(f"nft add element {family} filter {sname} {{ {', '.join(chunk)} }}")
    return cmds


def gen_ipt_cmds(v4: list[str], v6: list[str]) -> list[str]:
    cmds = []
    for net in v4:
        cmds.append(f"iptables -A INPUT -s {net} -j DROP")
    for net in v6:
        cmds.append(f"ip6tables -A INPUT -s {net} -j DROP")
    return cmds


def main() -> None:
    parser = argparse.ArgumentParser(description="读取指定文件内的 IP 进行封禁（一行一个 IP）")
    parser.add_argument("file", help="IP 列表文件路径")
    parser.add_argument(
        "--backend", choices=["nftables", "iptables"], default="nftables",
        help="防火墙后端（默认 nftables）",
    )
    parser.add_argument(
        "--apply", action="store_true",
        help="实际执行封禁（默认只打印命令）",
    )
    args = parser.parse_args()

    setup_logging()

    path = Path(args.file)
    if not path.exists():
        logger.error("文件不存在: %s", args.file)
        sys.exit(1)

    ips = []
    with open(path) as f:
        for line in f:
            normalized = normalize_ip(line)
            if normalized:
                ips.append(normalized)

    if not ips:
        logger.error("文件中没有找到有效的 IP 地址: %s", args.file)
        sys.exit(1)

    v4 = [ip for ip in ips if ipaddress.ip_network(ip, strict=False).version == 4]
    v6 = [ip for ip in ips if ipaddress.ip_network(ip, strict=False).version == 6]

    cmds = gen_nft_cmds(v4, v6) if args.backend == "nftables" else gen_ipt_cmds(v4, v6)

    print(f"\n{'=' * 60}")
    print(f"  封禁文件:   {args.file}")
    print(f"  后端:       {args.backend}")
    print(f"  IPv4 数量:  {len(v4)}")
    print(f"  IPv6 数量:  {len(v6)}")
    print(f"{'=' * 60}")
    for cmd in cmds:
        print(f"    {cmd}")
    print(f"{'=' * 60}")

    if args.apply:
        for cmd in cmds:
            try:
                subprocess.run(cmd, shell=True, check=True, timeout=60)
            except Exception as e:
                logger.error("命令执行失败: %s (%s)", cmd, e)
                sys.exit(1)
        logger.info("所有 IP 封禁规则已成功应用")
    else:
        logger.info("使用 --apply 参数来实际执行封禁")


if __name__ == "__main__":
    main()
