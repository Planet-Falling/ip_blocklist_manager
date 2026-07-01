# IP Blocklist Manager

![Python](https://img.shields.io/badge/Python-3.12%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-orange)

**IP 黑名单管理工具** — 自动从多个权威源下载恶意 IP 列表，合并去重后写入防火墙规则（iptables/nftables），支持 IPv4/IPv6 双栈。

---

## 支持的威胁情报源

| 来源 | 更新频率 | 内容 | 格式 |
|------|---------|------|------|
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | 实时 | 被劫持/犯罪控制的 IP 网段，误报极低 | TXT + JSON (v4/v6) |
| [FireHOL](https://github.com/firehol/blocklist-ipsets) | ~1 分钟 | 多级别聚合黑名单（Level 1-3, Webclient, Webserver, Anonymous） | netset |
| [Blocklist.de](https://www.blocklist.de/) | 30 分钟 | 众包攻击 IP（SSH/邮件/Web/FTP/暴力破解/爬虫等 8 类） | 纯文本 |
| [DShield / SANS ISC](https://feeds.dshield.org/) | 每日 | SANS 互联网风暴中心全球攻击源 | block.txt |

## 快速开始

```bash
git clone https://github.com/yourname/ip-blocklist-manager.git
cd ip-blocklist-manager

# 零外部依赖，直接运行
python3 main.py update
```

## 命令

```bash
python3 main.py [命令] [选项]
```

| 命令 | 说明 |
|------|------|
| `update` | 单次更新：下载 → 合并 → 写入防火墙 |
| `daemon` | 守护进程模式，按间隔自动更新 |
| `status` | 查看当前黑名单状态和防火墙规则数 |
| `flush`  | 清空所有防火墙规则 |

### 选项

| 选项 | 说明 |
|------|------|
| `-c, --config PATH` | 指定配置文件路径 |
| `-f, --force`       | 强制完全更新 |

### 示例

```bash
# 单次更新
python3 main.py update

# 后台持续运行
python3 main.py daemon

# 使用自定义配置
python3 main.py -c /etc/ip-blocklist/config.json update

# 查看状态
python3 main.py status
```

## 配置

默认配置文件 `config.json`：

```json
{
  "general": {
    "data_dir": "/var/lib/ip-blocklist",
    "log_level": "INFO",
    "ipv6_enabled": true
  },
  "firewall": {
    "backend": "nftables",
    "chain_v4": "BLOCKLIST_V4",
    "chain_v6": "BLOCKLIST_V6",
    "table": "filter",
    "flush_on_update": true
  },
  "sources": {
    "spamhaus": { "enabled": true, "update_interval": 3600 },
    "firehol": { "enabled": true, "update_interval": 300 },
    "blocklist_de": { "enabled": true, "update_interval": 1800 },
    "dshield": { "enabled": true, "update_interval": 86400 }
  }
}
```

### 防火墙后端

| 值 | 说明 |
|----|------|
| `nftables` | **默认**，使用 nftables set 批量添加 |
| `iptables` | 使用 iptables/ip6tables 链 |
| `none`     | 仅下载合并，不操作防火墙 |

## 数据源管理

### 启用/禁用数据源

在 `sources` 中设置 `"enabled": false` 即可关闭对应源。

### FireHOL 级别控制

```json
"firehol": {
  "levels": [
    {"level": 1, "enabled": true},
    {"level": 2, "enabled": true},
    {"level": 3, "enabled": false},
    {"level": "webclient", "enabled": false},
    {"level": "webserver", "enabled": false},
    {"level": "anonymous", "enabled": false}
  ]
}
```

### Blocklist.de 分类控制

```json
"blocklist_de": {
  "enabled_categories": ["all"]
}
```

可选分类：`all`, `ssh`, `mail`, `apache`, `imap`, `ftp`, `bruteforcelogin`, `bots`

## 架构

```
main.py (CLI + 调度)
  └── config.py (加载 JSON 配置)
  └── ip_manager.py (IP 去重、CIDR 合并、持久化)
  └── firewall.py (iptables / nftables 后端)
  └── sources/
      ├── base.py (基类：带重试的 HTTP 获取、缓存)
      ├── spamhaus.py (Spamhaus DROP 解析器)
      ├── firehol.py (FireHOL netset 解析器)
      ├── blocklist_de.py (Blocklist.de 解析器)
      └── dshield.py (DShield 范围解析器)
  └── utils.py (格式化、CIDR 合并、文件 I/O)
```

## 运行测试

```bash
python3 -m unittest test_ipblocklist.py -v
```

## 许可证

MIT License

---

**数据来源版权声明：** 本工具使用的所有威胁情报数据归各原始作者所有。Spamhaus DROP 要求在产品中注明来源，使用时请遵守各数据源的使用条款。
