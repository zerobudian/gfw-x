# GFW X

> The firewall evolves. So does the gateway.

**GFW X** 是一个高性能网络策略网关，面向你自己拥有或被授权管理的网络环境。
它提供三档运行模式、基于规则的策略引擎、VPN/Tunnel 检测、可控 DPI、异步日志，
以及一个内嵌在单一二进制中的 Web 管理面板。

- **单二进制**：Go 后端 + React/TypeScript 管理面板，前端产物通过 `go:embed` 打进同一可执行文件。
- **三模式实时切换**：`bypass` / `block` / `custom`，使用轻量、线程安全的原子状态切换，无需重启。
- **Fast Path / Slow Path**：已知流量一次分类后走缓存，未知/可疑/抽样流量走检测慢通道。
- **开箱即安全**：默认只监听 localhost，支持管理员认证、CSRF/Origin 防护、隐私脱敏导出。

---

## 目录

1. [功能总览](#功能总览)
2. [项目结构](#项目结构)
3. [构建与运行](#构建与运行)
4. [CLI](#cli)
5. [配置](#配置)
6. [规则系统](#规则系统)
7. [模式切换](#模式切换)
8. [VPN / Tunnel 检测](#vpn--tunnel-检测)
9. [日志系统](#日志系统)
10. [Web 管理面板](#web-管理面板)
11. [安全说明](#安全说明)
12. [部署](#部署)
13. [性能](#性能)
14. [常见问题](#常见问题)

---

## 功能总览

| 模块 | 说明 |
| --- | --- |
| 运行模式 | `bypass` / `block` / `custom`，Web 面板一键实时切换 |
| 规则引擎 | Domain / Suffix / IP / CIDR / ASN / Protocol / DNS / SNI / 分类 |
| 规则动作 | Allow / Block / Observe / Rate Limit |
| 优先级 | explicit allow > explicit block > category rule > default policy |
| 预置模板 | Balanced / Strict / Developer / Minimal / Custom |
| Fast/Slow Path | flow 缓存 + 固定 worker pool + 有界队列；unknown/suspicious/sampled 走慢通道 |
| 检测引擎 | WireGuard / OpenVPN / SOCKS / HTTP CONNECT / QUIC / MASQUE 及行为特征 |
| DPI | 仅对 unknown/suspicious/抽样(默认 2%) 流量做协议 & 元数据分析 |
| 日志 | 异步 pipeline，event → ring buffer → batch writer → storage（JSONL/CSV/Ring） |
| Web 面板 | Dashboard / Traffic / Rules / VPN / Logs / Analytics / Devices / Import-Export / Settings |
| 主题 | System / Light / Dark（跟随 `prefers-color-scheme`） |
| 语言 | zh-CN / English / System（默认读浏览器语言，全部 i18n key） |
| 安全 | 默认 LAN/localhost、管理员认证、CSRF/Origin、输入校验、隐私脱敏 |
| CLI | `run` / `validate` / `bench` / `export` / `version` |

---

## 项目结构

```
gfw-x/
├── cmd/gfwx/            # 程序入口
├── internal/
│   ├── gateway/         # 网关主循环、Fast/Slow Path、流量生成器
│   ├── flow/            # 分片 flow table / 分类决策
│   ├── policy/          # 策略与默认策略
│   ├── rules/           # 规则解析、仓库、冲突检测、预置模板、基准
│   ├── detect/          # VPN/Tunnel 检测引擎
│   ├── dpi/             # DPI（仅协议/元数据）
│   ├── dns/             # DNS 辅助
│   ├── tls/             # TLS SNI 提取
│   ├── logging/         # 异步日志 pipeline + 文件轮转
│   ├── metrics/         # 指标与实时事件环
│   ├── api/             # HTTP API + 认证 + CSRF + 静态托管(dist 已 embed)
│   ├── bench/           # gfwx bench
│   ├── export/          # 导出 / Diagnostic ZIP
│   ├── config/          # YAML/JSON 配置加载与校验
│   └── version/         # 版本信息
├── web/                 # React + TypeScript 管理面板（Vite 构建到 internal/api/dist）
├── configs/
│   ├── config.yaml      # 默认配置
│   └── rules/           # developer.txt / custom.txt 等规则文件
├── scripts/             # 辅助脚本
├── data/                # 运行时日志（默认 gitignore）
├── tests/               # 附加集成测试
├── go.mod
├── Makefile
├── Dockerfile
├── .github/workflows/   # CI / Release
└── README.md
```

---

## 构建与运行

### 前置要求

- Go 1.22+（推荐 1.25）
- 构建 Web 面板需要 Node 18+（可选：直接用已构建产物 `internal/api/dist`）
- Linux 为主要运行平台；macOS / Windows 可正常开发与调试

### 一键构建（Web + 二进制）

```bash
make build          # web build + go build，产出 ./gfwx
```

或分别执行：

```bash
cd web && npm install && npm run build   # 生成 internal/api/dist
cd .. && go build -o gfwx ./cmd/gfwx
```

> 注意：`internal/api/server.go` 通过 `//go:embed dist/*` 内嵌前端。若改动前端，
> 需要先重新构建 `internal/api/dist` 再编译二进制。

### 运行

```bash
# 使用默认配置（configs/config.yaml）
./gfwx run

# 指定配置 + 指定启动模式
./gfwx run --config configs/config.yaml --mode block

# 关闭内置的演示流量生成器（生产建议 --no-gen）
./gfwx run --no-gen --pprof

# 用离线抓包（经典 .pcap）作为真实流量输入，取代合成生成器
./gfwx run --pcap ./sample.pcap --pcap-rate 1000
```

`--pcap` 提供**真实流量输入**：用纯 Go（gopacket/pcapgo，无需 root / cgo）离线读取 classic `.pcap`，
逐帧解码（Ethernet / IPv4 / IPv6 + TCP / UDP）并经数据面过滤，可用于对真实流量的策略评估与演示。
`--pcap-rate N` 可选地限速到 N 包/秒（0 = 不限速）。
> 抓包示例：`tcpdump -i eth0 -w sample.pcap`（或 Wireshark 导出 `.pcap`）。支持 classic 格式。

启动后打开：<http://127.0.0.1:8443> （默认账号 `admin` / 密码 `admin`，请尽快修改）。

### 校验配置与规则

```bash
./gfwx validate --config configs/config.yaml --rules configs/rules/developer.txt
```

### 跑基准

```bash
./gfwx bench --flows 20000 --workers 4
```

### 导出

```bash
# 导出规则/配置/日志到目录
./gfwx export --dir ./export --redact

# 打成诊断 ZIP
./gfwx export --zip --redact
```

---

## CLI

```
gfwx run                         启动网关 + Web 面板
gfwx run --mode bypass|block|custom
gfwx run --pcap sample.pcap [--pcap-rate N]   离线回放抓包作为真实流量输入
gfwx run --no-gen --pprof                    关闭合成生成器 / 开启 pprof
gfwx validate --config ... --rules ...
gfwx bench --flows N --workers N
gfwx export [--zip] [--redact] [--dir ...]
gfwx version                      打印版本
```

---

## 配置

配置文件支持 **YAML / JSON**（按扩展名自动识别）。默认配置见
[configs/config.yaml](configs/config.yaml)。

关键字段：

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `defaults.mode` | `block` | 默认运行模式 |
| `defaults.theme` | `system` | system/light/dark |
| `defaults.lang` | `system` | system/zh-CN/en |
| `defaults.dpi_sample_ratio` | `0.02` | 未知/可疑流量的 DPI 抽样比例 |
| `server.listen` | `127.0.0.1:8443` | 只监听本机 |
| `server.lan_only` | `true` | 是否仅限 LAN/localhost |
| `server.auth` | see file | 管理员认证 |
| `logging.format` | `jsonl` | jsonl/csv/ring |
| `logging.dir` | `data/logs` | 日志目录 |
| `logging.max_bytes` | 104857600 | 单文件轮转阈值 |
| `logging.max_files` | 10 | 保留文件数 |
| `logging.redact` | `true` | 不保存 payload；导出默认脱敏 |
| `runtime.flow_shards` | 32 | flow table 分片，避免全局锁 |
| `runtime.worker_pool` | 4 | 固定 worker pool |
| `runtime.channel_capacity` | 8192 | 有界队列 |
| `detect.enabled` | `true` | 检测引擎开关 |
| `detect.auto_action` | `observe` | 检测命中后的动作 |
| `detect.confidence_threshold` | `0.85` | 低于该置信度不自动处置 |
| `rules_file` | developer 预设 | 启动时加载的规则 |
| `custom_rules_file` | custom.txt | Custom 模式规则 |

> 密码哈希为 SHA-256 双重加盐。默认 `admin/admin`，**上线前务必更换**，
> 并将 `server.auth.session_token` 设为随机十六进制（为空时启动会随机生成）。

---

## 规则系统

### 匹配类型

| 匹配字段 | 说明 |
| --- | --- |
| `domain` | 精确域名 |
| `domain_sfx` / `*.example.com` | 后缀 / 通配符匹配 |
| `ip` | 单 IP |
| `cidr` | CIDR |
| `asn` | ASN |
| `protocol` | 传输/应用协议 |
| `dns` | DNS 查询 |
| `sni` | TLS SNI |
| `category` | 规则分类 |
| `wildcard` | 通配符 |

### 规则动作

`allow` / `block` / `observe` / `ratelimit`

### 优先级

顺序判断：

```
explicit allow > explicit block > category rule > default policy
```

即：显式放行优先于显式拦截，显式拦截优先于分类规则，分类规则最后兜底到默认策略。

### TXT 格式示例（见 configs/rules/developer.txt）

```text
# 分类拦截
BLOCK_CATEGORY adult
BLOCK_CATEGORY gambling
BLOCK_CATEGORY malicious
BLOCK_CATEGORY vpn-tunnel

# 显式放行
ALLOW *.openai.com
ALLOW *.github.com
ALLOW *.pages.dev

# 显式拦截
BLOCK example.com
```

导入流程为：`parse → validate → conflict detection → preview → apply`，
**不会**在导入后直接覆盖运行配置，需在预览确认后应用。

---

## 模式切换

- **Bypass**：完全不拦截，只统计与记录。
- **Block**：启用当前规则集。
- **Custom**：使用自定义策略（custom_rules_file）。

切换通过 Web 面板一键完成，使用 `atomic` 运行状态实现，**不重建服务、不中断数据面**。

---

## VPN / Tunnel 检测

独立 Detection Engine（`internal/detect`），**检测与处置分离**。

检测对象：WireGuard、OpenVPN、SOCKS、HTTP CONNECT、QUIC/HTTP3 tunnel、
MASQUE/CONNECT-UDP、未知加密隧道。

行为特征：包长分布、方向序列、连接时长、keepalive 模式、突发间隔、上下行比例。

处置动作：`allow` / `observe` / `ratelimit` / `reject` / `drop`。

> **安全默认**：即使开启检测，也只对置信度 ≥ `confidence_threshold` 的流量应用自动动作，
> 默认 `auto_action=observe`，**不会因低置信度直接阻断**。不使用“端口猜 VPN”式简单判断。

---

## 日志系统

异步 pipeline：

```
event → ring buffer / queue → batch writer → storage
```

- 支持 JSONL / CSV / Ring（内置）
- 文件轮转 + 最大空间限制（max_bytes / max_files）
- 记录：timestamp、src、dst、protocol、domain/SNI、action、matched rule、检测置信度、上下行字节、duration
- 高压力自动降级：`full metadata → sampled metadata → counters only`
- 日志永不阻塞网关转发，不做 payload/DNS 明文/TLS 明文记录

---

## Web 管理面板

| 页面 | 内容 |
| --- | --- |
| Dashboard | 模式、实时吞吐、Allowed/Blocked/Unknown、活跃 flow、今日拦截、Top domains、Top block reasons、协议分布、VPN 检测、CPU/RAM、实时事件 |
| Traffic | 流量明细与统计 |
| Rules | 新增/修改/删除/启停/搜索/分类/复制/命中次数/最后命中/冲突检查 |
| VPN Detection | 检测引擎输出与置信度 |
| Logs | 异步日志查看 |
| Analytics | 聚合分析 |
| Devices | 设备维度 |
| Import / Export | 导入导出 + Diagnostic ZIP |
| Settings | 模式、主题、语言、认证 |

- **主题**：System / Light / Dark，提供 `prefers-color-scheme`。
- **语言**：zh-CN / English / System，默认读浏览器语言，UI 全部走 i18n key。

---

## 安全说明

- Web Dashboard **默认只监听 localhost / LAN**，不自动暴露公网。
- 支持管理员认证；API 全部做权限检查。
- 变更请求做 **CSRF / Origin 防护**。
- 导出日志默认提供**隐私脱敏**（`--redact` / Settings 选项）。
- **不默认保存 payload**，不记录消息正文或 TLS 明文。
- 所有输入做校验；规则/配置导入防止路径穿越、命令注入、配置注入。

---

## 部署

### Docker

```bash
docker build -t gfw-x .
docker run --rm -p 8443:8443 gfw-x run --config /data/config.yaml
```

> 生产建议把 `configs`、`data` 挂载为卷，并覆盖默认密码。

### systemd

```bash
sudo cp configs/gfw-x.service /etc/systemd/system/
# 按需修改 ExecStart 的工作目录与路径
sudo systemctl daemon-reload
sudo systemctl enable --now gfwx
```

### Makefile 常用目标

```bash
make build      # 构建二进制（含 web）
make web        # 仅构建前端
make test       # 运行单元测试 + 基准
make bench      # 运行性能基准
make vet        # go vet
make release    # 多平台交叉编译 + 压缩包
make docker     # 构建 Docker 镜像
make clean      # 清理产物
```

---

## 性能

`gfwx bench` 输出：

- flows/sec
- packets/sec
- throughput (Gbps)
- policy decision p50/p95/p99
- allocations/op
- memory
- DPI enabled/disabled delta

设计上：flow 一次分类、Domain exact 用 hash map、后缀用 reversed trie/radix、CIDR 用 radix、
flow table 分片、固定 worker pool、有界 channel、热路径低 allocation、日志异步化、支持 pprof。

---

## 常见问题

**1. 前端改动后二进制里没生效？**
需要先 `cd web && npm run build`（生成 `internal/api/dist`），再重新编译 Go 二进制。

**2. 默认密码是？**
`admin` / `admin`。请立即在 Settings 中修改，并替换 config.yaml 的密码哈希与 session token。

**3. 监听不了 8443？**
修改 `configs/config.yaml` 中的 `server.listen`。

**4. 想开放给局域网？**
设置 `server.listen: 0.0.0.0:8443` 且 `server.lan_only: false`，并务必启用认证与 HTTPS 反向代理，避免暴露公网。

---

## License

GFW X 采用自定义的**开源许可协议**（[LICENSE](LICENSE)，Open Source，源码公开可自由获取/研究/修改/再分发），
并施加以下明确的**使用限制**，任何下载、部署、使用即表示你同意接受这些约束：

- **特别禁止：中国政府及其相关方**——中华人民共和国政府及其一切机关、
  部门、直属/附属机构、军队、警察、国安、司法、情报、海关/边检、移民与
  监察机关，以及任何受其委托、资助、指示、采购、控股或以其他名义行事的
  供应商、承包商、代理、外包方与关联方，**严禁使用本软件的任何一行代码、
  产物、文档或派生作品**（详见 [LICENSE](LICENSE) 首要条款）。
- **禁止商用**：不得用于任何营利、收费或商业化活动。
- **禁止政府与公共部门使用**：不得由任何国家和地区政府部门、机关、事业单位、
  公营机构或其委托/资助方使用、部署、运营、维护或改造。
- **禁止执法 / 军事 / 情报用途**：不得用于警察、司法、军队、国安、情报、
  海关/边检、移民、监控或任何执法与国土安全用途。
- **禁止政治性与审查用途**：不得用于政治审查、舆论控制、网络过滤、内容监控
  与屏蔽、社会控制、公民追踪或任何形式的政治打压 / 言论管制。
- **禁止规避用途**：不得通过改造、换皮、改名、分叉后继续从事上述任一禁止
  用途，或以任何方式协助他人规避上述限制。

**允许**：个人学习、教学、科研及非商业演示与评估使用（须保留版权声明与协议）。

GFW X 面向**用户自己拥有或被授权管理的**网络环境。请遵守当地法律法规并以
授权使用为前提。违反上述限制将自动、立即终止授权。如需在上述禁止范围内使用，
请先获得著作权人的书面许可。