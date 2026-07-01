#!/usr/bin/env python3

import argparse
import logging
import os
import signal
import sys
import time
from pathlib import Path

from config import resolve_config
from ip_manager import IPManager
from firewall import get_firewall_backend, check_env, prompt_backend
from sources.spamhaus import SpamhausSource
from sources.firehol import FireHOLSource
from sources.blocklist_de import BlocklistDeSource
from sources.dshield import DShieldSource

logger = logging.getLogger("ip-blocklist")


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def create_sources(config: dict, data_dir: str) -> list:
    sources = []
    src_cfg = config.get("sources", {})

    spamhaus_cfg = src_cfg.get("spamhaus", {})
    if spamhaus_cfg.get("enabled", True):
        sources.append(SpamhausSource(spamhaus_cfg, data_dir))

    firehol_cfg = src_cfg.get("firehol", {})
    if firehol_cfg.get("enabled", True):
        sources.append(FireHOLSource(firehol_cfg, data_dir))

    blocklist_de_cfg = src_cfg.get("blocklist_de", {})
    if blocklist_de_cfg.get("enabled", True):
        sources.append(BlocklistDeSource(blocklist_de_cfg, data_dir))

    dshield_cfg = src_cfg.get("dshield", {})
    if dshield_cfg.get("enabled", True):
        sources.append(DShieldSource(dshield_cfg, data_dir))

    return sources


def run_update(config: dict, force: bool = False, apply: bool = False) -> bool:
    general = config.get("general", {})
    data_dir = general.get("data_dir", "/var/lib/ip-blocklist")
    Path(data_dir).mkdir(parents=True, exist_ok=True)

    ipv6_enabled = general.get("ipv6_enabled", True)
    max_entries = general.get("max_memory_entries", 1_000_000)

    ipm = IPManager(data_dir, max_entries)

    if apply:
        env_info = check_env()
        chosen = prompt_backend(config, env_info)
        # Temporarily override the config backend
        config.setdefault("firewall", {})["backend"] = chosen
        if chosen == "none":
            logger.info("Firewall backend set to none, skipping firewall rules")

    firewall_config = config.get("firewall", {})
    fw = get_firewall_backend(firewall_config)

    sources = create_sources(config, data_dir)
    if not sources:
        logger.error("No sources enabled in config.yaml")
        return False

    logger.info("Starting update with %d source(s)", len(sources))

    for source in sources:
        ok = source.update()
        if ok:
            ipm.add_source_networks(source.name, source.get_networks())
        else:
            logger.warning("Skipping %s (download failed)", source.name)

    merged = ipm.merge()
    ipm.save_merged()

    if fw and merged:
        v4_nets = ipm.get_v4_networks()
        v6_nets = ipm.get_v6_networks() if ipv6_enabled else []

        cmds = fw.generate_apply_commands(v4_nets, v6_nets)
        print(f"\n{'=' * 60}")
        print(f"  Firewall rules to block {len(v4_nets)} IPv4 + {len(v6_nets)} IPv6 networks")
        print(f"  Backend: {firewall_config.get('backend', 'nftables')}")
        print(f"{'=' * 60}")
        fw.print_commands(cmds)
        print(f"{'=' * 60}")

        if apply:
            resp = input("Apply these rules? [y/N] ").strip().lower()
            if resp == "y":
                if fw.execute_commands(cmds):
                    logger.info("Firewall rules applied successfully")
                else:
                    logger.error("Some firewall commands failed")
            else:
                logger.info("Skipped applying firewall rules")
        else:
            logger.info("Use --apply to apply these firewall rules")

    logger.info("Update complete: %d total networks", len(merged))
    return True


def run_once(config_path: str | None = None, apply: bool = False) -> None:
    config = resolve_config(config_path)
    setup_logging(config.get("general", {}).get("log_level", "INFO"))
    run_update(config, apply=apply)


def run_daemon(config_path: str | None = None) -> None:
    config = resolve_config(config_path)
    setup_logging(config.get("general", {}).get("log_level", "INFO"))
    general = config.get("general", {})
    data_dir = general.get("data_dir", "/var/lib/ip-blocklist")

    logger.info("Starting IP Blocklist Manager daemon (firewall rules not auto-applied in daemon mode)")

    run_update(config)

    sources = create_sources(config, data_dir)
    if not sources:
        logger.error("No sources enabled, exiting")
        sys.exit(1)

    shutdown_flag = [False]

    def signal_handler(signum, frame):
        logger.info("Received signal %s, shutting down...", signum)
        shutdown_flag[0] = True

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    intervals = []
    for source in sources:
        interval = source.config.get("update_interval", 3600)
        intervals.append(interval)
        logger.info(
            "  %s: every %d seconds",
            source.name,
            interval,
        )

    min_interval = min(intervals) if intervals else 300

    logger.info("Daemon running (check interval: %ds)", min_interval)
    last_update = time.time()

    while not shutdown_flag[0]:
        now = time.time()
        should_update = False

        for source in sources:
            interval = source.config.get("update_interval", 3600)
            if now - source.last_update >= interval:
                should_update = True
                break

        if should_update:
            run_update(config)
            last_update = now

        try:
            time.sleep(min(min_interval, 30))
        except KeyboardInterrupt:
            break

    logger.info("Daemon stopped")


def show_status(config_path: str | None = None) -> None:
    config = resolve_config(config_path)
    general = config.get("general", {})
    data_dir = general.get("data_dir", "/var/lib/ip-blocklist")

    ipm = IPManager(data_dir)
    ipm.load_merged()

    print(f"\n{'=' * 50}")
    print(f"  IP Blocklist Manager - Status")
    print(f"{'=' * 50}")
    print(f"  Data directory: {data_dir}")
    print(f"  Total networks: {ipm.total_count}")
    print(f"  IPv4 networks:  {ipm.count_v4}")
    print(f"  IPv6 networks:  {ipm.count_v6}")
    print()

    fw_config = config.get("firewall", {})
    fw = get_firewall_backend(fw_config)
    if fw:
        stats = fw.show_stats()
        for family, stat in stats.items():
            rules = stat.get("rules", 0)
            print(f"  {family} rules: {rules}")
    else:
        print("  Firewall: disabled")

    print(f"{'=' * 50}\n")


def flush_firewall(config_path: str | None = None, apply: bool = False) -> None:
    config = resolve_config(config_path)

    if apply:
        env_info = check_env()
        chosen = prompt_backend(config, env_info)
        config.setdefault("firewall", {})["backend"] = chosen

    fw_config = config.get("firewall", {})
    fw = get_firewall_backend(fw_config)
    if not fw:
        logger.info("No firewall backend configured")
        return

    cmds = fw.generate_flush_commands()
    print(f"\n{'=' * 60}")
    print(f"  Commands to flush blocklist firewall rules")
    print(f"{'=' * 60}")
    fw.print_commands(cmds)
    print(f"{'=' * 60}")

    if apply:
        resp = input("Flush these rules? [y/N] ").strip().lower()
        if resp == "y":
            if fw.execute_commands(cmds):
                logger.info("Firewall rules flushed successfully")
            else:
                logger.error("Some flush commands failed")
        else:
            logger.info("Skipped flushing firewall rules")
    else:
        logger.info("Use --apply to execute these flush commands")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="IP Blocklist Manager - Download, merge, and apply IP blocklists",
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to configuration file",
    )
    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Force full update even if not due",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually apply firewall rules (default: dry-run, only print commands)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    subparsers.add_parser("update", help="Run a single update cycle")
    subparsers.add_parser("daemon", help="Run as continuous daemon")
    subparsers.add_parser("status", help="Show current blocklist status")
    subparsers.add_parser("flush", help="Remove all firewall rules")

    args = parser.parse_args()
    if args.command == "update":
        run_once(args.config, apply=args.apply)
    elif args.command == "daemon":
        run_daemon(args.config)
    elif args.command == "status":
        show_status(args.config)
    elif args.command == "flush":
        flush_firewall(args.config, apply=args.apply)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
