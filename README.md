# IP Blocklist Manager

![Python](https://img.shields.io/badge/Python-3.12%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-orange)

**IP 黑名单管理工具** — 自动从多个权威源下载恶意 IP 列表，合并去重后生成防火墙规则（iptables/nftables），默认 dry-run 确保安全，支持 IPv4/IPv6 双栈。

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

# 零外部依赖，直接运行（dry-run 模式，仅打印命令）
python3 main.py update

# 确认命令无误后，加 --apply 实际写入防火墙
python3 main.py --apply update
```

## 命令

```bash
python3 main.py [命令] [选项]
```

| 命令 | 说明 |
|------|------|
| `update` | 单次更新：下载 → 合并 → 展示防火墙命令（默认不执行） |
| `daemon` | 守护进程模式，按间隔自动更新（不操作防火墙） |
| `status` | 查看当前黑名单状态和防火墙规则数 |
| `flush`  | 展示清空防火墙规则的命令（默认不执行） |

### 选项

| 选项 | 说明 |
|------|------|
| `-c, --config PATH` | 指定配置文件路径 |
| `-f, --force`       | 强制完全更新 |
| `--apply`           | 实际执行防火墙规则（默认 dry-run，仅打印命令） |

### 示例

```bash
# 下载合并，展示防火墙命令（不执行）
python3 main.py update

# 下载合并，询问确认后写入防火墙
python3 main.py --apply update

# 后台持续运行（不操作防火墙）
python3 main.py daemon

# 使用自定义配置
python3 main.py -c /etc/ip-blocklist/config.json update

# 查看状态
python3 main.py status

# 展示清空命令（不执行）
python3 main.py flush

# 清空防火墙规则（询问确认后执行）
python3 main.py --apply flush
```

> **安全说明：** `update` 和 `flush` 默认均为 **dry-run 模式**，只打印要执行的命令，不会实际改动防火墙。确认无误后加 `--apply` 才会进入交互流程：
> 1. 环境检测（Docker 状态、iptables 模式）
> 2. 如果检测到冲突（如 Docker 运行中但 iptables 为 legacy 模式），**自动推荐 nftables 后端**，并让用户选择
> 3. 展示将要执行的防火墙命令
> 4. 用户输入 `y` 确认后才实际执行

## 快速封禁自定义 IP 列表

```bash
python3 ban_ip_file.py ip_list.txt              # dry-run，仅打印命令
sudo python3 ban_ip_file.py ip_list.txt --apply # 实际执行封禁
```

从指定文件读取 IP（一行一个），追加到 nftables `blocklist_v4`/`blocklist_v6` 集合中，与自动更新的黑名单共存。

| 选项 | 说明 |
|------|------|
| `--backend` | 防火墙后端，可选 `nftables`（默认）或 `iptables` |
| `--apply`   | 实际执行封禁（默认 dry-run，仅打印命令） |

文件格式示例：
```
1.1.1.1
8.8.8.0/24
2001:db8::1
# 这是注释
; 这也是注释
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
    "backend": "nftables"
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
| `nftables` | **默认**，使用 nftables set + INPUT 链 drop 规则，不创建新链，不影响 Docker |
| `iptables` | 使用 iptables/ip6tables 直接向 INPUT 链添加 DROP 规则 |
| `none`     | 仅下载合并，不操作防火墙 |

> 新版本防火墙规则**不会创建自定义链**，也不会修改 INPUT 链的跳转关系，仅向 INPUT 链追加 IP 源地址丢弃规则，不干扰 Docker、NAT 等现有规则。

### Docker 兼容性

`--apply` 执行前会自动检测环境：

- **Docker 运行检测**：检查 `/var/run/docker.sock` 和 `docker ps`
- **iptables 模式检测**：检查当前 `iptables` 是 `legacy` 还是 `nf_tables` 模式
- 如果 Docker 运行中但 iptables 处于 legacy 模式，**强烈建议使用 nftables 后端**，否则可能导致 Docker 网络规则冲突
- 交互提示让用户选择后端：`nftables` / `iptables` / `none`

> Docker 容器流量走 `FORWARD` 链，本工具的封禁规则只在 `INPUT` 链生效，**不会误拦转发到容器的流量**。

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
main.py (CLI + 调度，--apply 时交互选后端)
ban_ip_file.py (独立脚本：读取文件 IP 追加封禁)
  └── config.py (加载 JSON 配置)
  └── ip_manager.py (IP 去重、CIDR 合并、持久化)
  └── firewall.py
  │   ├── NftablesBackend (默认：nftables sets)
  │   ├── IptablesBackend (备选：iptables INPUT 规则)
  │   └── check_env() / prompt_backend() (环境检测 + 交互选后端)
  └── sources/
      ├── base.py (基类：带重试的 HTTP 获取、缓存)
      ├── spamhaus.py (Spamhaus DROP 解析器)
      ├── firehol.py (FireHOL netset 解析器)
      ├── blocklist_de.py (Blocklist.de 解析器)
      └── dshield.py (DShield 范围解析器)
  └── utils.py (格式化、CIDR 合并、文件 I/O)
```

### 防火墙规则原理

**nftables 后端**（默认）：
1. 创建 `blocklist_v4`/`blocklist_v6` 集合（`set`），类型为 `ipv4_addr` + `interval` flags
2. 向 `INPUT` 链添加一条规则：`ip saddr @blocklist_v4 counter drop`
3. 将封禁 IP 批量写入集合元素
4. 清空时：删除 INPUT 链中的引用规则 → 删除集合

**iptables 后端**：
1. 逐条向 `INPUT` 链添加 `-s IP -j DROP` 规则
2. 清空时：按行号反向删除 INPUT 链中的 DROP 规则

两种后端均**不创建自定义链**，不修改已有链结构，不影响 Docker、NAT 等现有规则。

> **为什么不使用 UFW？** UFW 的 `deny from <IP>` 每条规则独立添加，35,000+ 条规则会导致 `O(n)` 线性匹配，性能极差；且 `ufw reload` 会冲掉非 UFW 管理的规则。nftables set 的哈希查找是 `O(1)`，适合大规模封禁。

## 运行测试

```bash
python3 -m unittest test_ipblocklist.py -v
```

## 许可证

MIT License

---

**数据来源版权声明：** 本工具使用的所有威胁情报数据归各原始作者所有。Spamhaus DROP 要求在产品中注明来源，使用时请遵守各数据源的使用条款。
