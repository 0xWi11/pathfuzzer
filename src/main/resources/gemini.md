# Proxy Node Configuration Management Guide

## 操作原则（AI 必读！）

> **在执行任何任务之前，必须遵守以下原则：**

### 1. 禁止过度工程化

- **不要为简单任务编写脚本文件**（.py / .sh / .js 等）
- 如果任务可以用 1-2 行命令完成，直接执行，不要创建脚本
- 如果数据量小（<100 条），直接处理比写自动化脚本更高效

### 2. 直接编辑配置文件

- 使用文件编辑工具直接修改 `config20.json` 和 `haproxy.cfg`
- **不要**创建临时 Python/Shell 脚本来处理文件
- **不要**创建中间临时文件

### 3. AI 可直接解码 Base64

- SS/SSR/VMess 链接中的 Base64 **你可以直接在脑中解码**，不需要调用任何外部工具
- 示例：`YWVzLTEyOC1nY206cGFzc3dvcmQ=` = `aes-128-gcm:password`
- **禁止**使用 `python -c "import base64..."` 或 `echo ... | base64 -d`

### 4. 正确的工作流程

```
❌ 错误做法：
1. 编写 Python 脚本解析节点 URL
2. 创建临时文件存储中间结果
3. 执行脚本生成配置
4. 清理临时文件

✅ 正确做法：
1. 直接阅读并理解节点 URL（包括 Base64 部分）
2. 在响应中直接生成需要的配置内容
3. 使用编辑工具直接修改目标配置文件
```

### 5. 工具选择优先级

| 任务类型 | 推荐方法 | 禁止方法 |
|---------|---------|---------|
| Base64 解码 | 直接在脑中解码 | Python/Shell 脚本 |
| JSON 修改 | 直接编辑文件 | 写脚本处理 |
| 文本替换 | sed 单行命令或直接编辑 | 写 Python 脚本 |
| 批量节点处理 | 直接生成配置文本 | 写解析脚本 |

---

## 项目概述

本项目用于管理多订阅源的代理节点配置，包含两个核心配置文件：
- `config20.json` - Xray-core 代理客户端配置
- `haproxy.cfg` - HAProxy 负载均衡配置

两个配置文件必须保持同步：当 xray-core 配置中添加/删除/修改节点时，haproxy 配置也需要相应更新。

---

## 版本标识系统

节点按订阅源分为多个版本，每个版本使用固定的端口范围：

### 已定义版本

| 版本 | 端口范围 | xray-core tag 格式 | haproxy server 格式 | 说明 |
|------|----------|-------------------|---------------------|------|
| v1   | 108XX (10801-10899) | `{region}v1-{num}` 如 `hkv1-01` | `lb-{region}v1-{num}` 如 `lb-hkv1-01` | 主订阅源 |
| v2   | 168XX (16801-16899) | `{region}v2-{num}` 如 `hkv2-01` | `lb-{region}v2-{num}` 如 `lb-hkv2-01` | 订阅源2 |
| v3   | 166XX (16601-16699) | `{region}v3-{num}` 如 `hkv3-01` | `lb-{region}v3-{num}` 如 `lb-hkv3-01` | 订阅源3 |
| v4   | 161XX (16101-16299) | `{region}v4-{num}` 如 `hkv4-01` | `lb-{region}v4-{num}` 如 `lb-hkv4-01` | 订阅源4 |

### 预留版本（端口待定）

| 版本 | 端口范围 | xray-core tag 格式 | haproxy server 格式 | 说明 |
|------|----------|-------------------|---------------------|------|
| v5   | 待定 | `{region}v5-{num}` 如 `hkv5-01` | `lb-{region}v5-{num}` 如 `lb-hkv5-01` | 订阅源5 |
| v6   | 待定 | `{region}v6-{num}` 如 `hkv6-01` | `lb-{region}v6-{num}` 如 `lb-hkv6-01` | 订阅源6 |
| v7+  | 待定 | `{region}v{N}-{num}` | `lb-{region}v{N}-{num}` | 未来扩展 |

**所有版本的命名格式统一为 `{region}v{version}-{num}`，便于识别和管理。**

### 端口起始规则
- 每个版本的端口起始点是固定的，一旦确定不会改变
- v1: 从 10801 开始
- v2: 从 16801 开始
- v3: 从 16601 开始
- v4: 从 16101 开始
- v5+: 用户会在添加新版本时指定端口范围

### 添加新版本时的操作
当用户要添加新版本（如 v5）时，用户会提供：
1. 版本号（如 v5）
2. 端口范围（如 167XX，从 16701 开始）
3. 节点列表

AI 需要：
1. 记住该版本的端口范围
2. 按照统一的命名规则生成配置
3. 将节点添加到对应的 haproxy backend

---

## 地区代码对照表

| 地区 | 代码 | 地区 | 代码 | 地区 | 代码 |
|------|------|------|------|------|------|
| 香港 | hk | 台湾 | tw | 新加坡 | sg |
| 日本 | jp | 美国 | us | 韩国 | kr |
| 英国 | uk | 德国 | de | 法国 | fr |
| 荷兰 | nl | 意大利 | it | 西班牙 | es |
| 加拿大 | ca | 澳大利亚 | au | 俄罗斯 | ru |
| 土耳其 | tr | 阿根廷 | ar | 巴西 | br |
| 智利 | cl | 印度 | in | 以色列 | il |
| 泰国 | th | 越南 | vn | 马来西亚 | my |
| 菲律宾 | ph | 印尼 | id | 瑞士 | ch |
| 芬兰 | fi | 尼日利亚 | ng | 南非 | za |
| 乌克兰 | ua | 澳门 | mo | 狮城 | sg |

### 地区识别规则
从节点名称中识别地区时，使用以下关键词匹配：
- 🇭🇰 / 香港 / Hong Kong / HK → `hk`
- 🇹🇼 / 台湾 / 台灣 / Taiwan / TW → `tw`
- 🇸🇬 / 新加坡 / 狮城 / 獅城 / Singapore / SG → `sg`
- 🇯🇵 / 日本 / Japan / JP → `jp`
- 🇺🇸 / 美国 / 美國 / United States / US / USA → `us`
- 🇰🇷 / 韩国 / 韓國 / Korea / KR → `kr`
- 🇬🇧 / 英国 / 英國 / United Kingdom / UK / GB → `uk`
- 🇩🇪 / 德国 / 德國 / Germany / DE → `de`
- 🇦🇺 / 澳大利亚 / 澳洲 / 悉尼 / Australia / AU → `au`
- 🇲🇴 / 澳门 / 澳門 / Macau / MO → `mo`
- 🇮🇳 / 印度 / India / IN → `in`
- 等等...（根据实际节点名称推断）

---

## xray-core 配置结构

### 文件位置
```
config20.json
```

### 核心结构
```json
{
  "log": {...},
  "dns": {...},
  "inbounds": [...],    // 入站配置 - 本地监听端口
  "outbounds": [...],   // 出站配置 - 代理服务器连接
  "routing": {...}      // 路由规则 - 将入站流量转发到对应出站
}
```

### 每个节点需要配置的三个部分

#### 1. Inbound (入站配置)
**格式：单行压缩 JSON**
```json
{"tag":"{region}v{version}-{num}-in","port":{port},"listen":"127.0.0.1","protocol":"mixed","sniffing":{"enabled":false,"destOverride":["http","tls"],"routeOnly":false},"settings":{"auth":"noauth","udp":false,"allowTransparent":false}}
```

示例（v1 香港节点）：
```json
{"tag":"hkv1-01-in","port":10801,"listen":"127.0.0.1","protocol":"mixed","sniffing":{"enabled":false,"destOverride":["http","tls"],"routeOnly":false},"settings":{"auth":"noauth","udp":false,"allowTransparent":false}}
```

#### 2. Outbound (出站配置)
**格式：单行压缩 JSON**

根据协议类型不同，格式有所差异。常见协议：

**Trojan 协议：**
```json
{"tag":"{region}v{version}-{num}","protocol":"trojan","settings":{"servers":[{"address":"服务器地址","port":端口号,"password":"密码","level":1}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"allowInsecure":true,"serverName":"SNI域名"}},"mux":{"enabled":false,"concurrency":-1}}
```

示例（v1 香港节点）：
```json
{"tag":"hkv1-01","protocol":"trojan","settings":{"servers":[{"address":"server.example.com","port":20002,"password":"YOUR-PASSWORD","level":1}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"allowInsecure":true,"serverName":"sni.example.com"}},"mux":{"enabled":false,"concurrency":-1}}
```

**Shadowsocks 协议：**
```json
{"tag":"{region}v{version}-{num}","protocol":"shadowsocks","settings":{"servers":[{"address":"服务器地址","port":端口号,"method":"加密方式","password":"密码","level":1}]},"mux":{"enabled":false,"concurrency":-1}}
```

示例：
```json
{"tag":"hkv2-01","protocol":"shadowsocks","settings":{"servers":[{"address":"server.example.com","port":49500,"method":"aes-128-gcm","password":"1df33a15-be77-48ad-aac2-867a4fdab200","level":1}]},"mux":{"enabled":false,"concurrency":-1}}
```

**VMess 协议：**
```json
{"tag":"{region}v{version}-{num}","protocol":"vmess","settings":{"vnext":[{"address":"服务器地址","port":端口号,"users":[{"id":"UUID","alterId":0,"security":"auto","level":1}]}]},"streamSettings":{...},"mux":{"enabled":false,"concurrency":-1}}
```

#### 3. Routing Rule (路由规则)
**格式：单行压缩 JSON**
```json
{"type":"field","inboundTag":["{region}v{version}-{num}-in"],"outboundTag":"{region}v{version}-{num}"}
```

示例：
```json
{"type":"field","inboundTag":["hkv1-01-in"],"outboundTag":"hkv1-01"}
```

---

## haproxy 配置结构

### 文件位置
```
haproxy.cfg
```

### 核心结构
```
global
    ...

defaults
    ...

# 原有节点组 - 端口 20808 (v1 节点)
frontend proxy_front
    bind *:20808
    ...
    default_backend proxy_back

backend proxy_back
    ...
    # v1 节点（紧凑排列，无地区注释）
    server lb-hkv1-01 host.docker.internal:10801 weight 100
    server lb-hkv1-02 host.docker.internal:10802 weight 100
    server lb-twv1-01 host.docker.internal:10803 weight 100
    server lb-twv1-02 host.docker.internal:10804 weight 100
    ...

# 扩展节点组 - 端口 20668 (v2/v3/v4/... 节点)
frontend proxy_front_vx
    bind *:20668
    ...
    default_backend proxy_back_vx

backend proxy_back_vx
    ...
    # 所有 v2+ 节点紧凑排列，无地区注释
    server lb-hkv2-01 host.docker.internal:16801 weight 100
    server lb-hkv2-02 host.docker.internal:16802 weight 100
    server lb-jpv2-01 host.docker.internal:16803 weight 100
    server lb-hkv3-01 host.docker.internal:16601 weight 100
    server lb-hkv3-02 host.docker.internal:16602 weight 100
    server lb-hkv4-01 host.docker.internal:16101 weight 100
    ...
```

### 节点行格式
```
server lb-{region}v{version}-{num} host.docker.internal:{port} weight 100
```

所有版本使用统一的命名格式：`lb-{region}v{version}-{num}`

### haproxy 节点格式要求
- **不要添加地区注释**（如 `# Hong Kong v3 2 nodes`）
- **节点紧凑排列**，每行一个节点，行与行之间无空行
- 按版本和地区有序排列即可，无需额外注释

---

## 代理节点 URL 解析

### 常见协议 URL 格式

#### Shadowsocks (ss://)
```
ss://{base64(method:password)}@{server}:{port}#{name}
或
ss://{base64(method:password@server:port)}#{name}
```

解析示例：
```
ss://YWVzLTEyOC1nY206MWRmMzNhMTUtYmU3Ny00OGFkLWFhYzItODY3YTRmZGFiMjAw@auto-route.example.com:49500#🇭🇰 香港 01
```
- Base64 解码: `aes-128-gcm:1df33a15-be77-48ad-aac2-867a4fdab200`
- method: `aes-128-gcm`
- password: `1df33a15-be77-48ad-aac2-867a4fdab200`
- server: `auto-route.example.com`
- port: `49500`
- name: `🇭🇰 香港 01`

#### Trojan (trojan://)
```
trojan://{password}@{server}:{port}?{params}#{name}
```

#### VMess (vmess://)
```
vmess://{base64(json_config)}
```

#### VLESS (vless://)
```
vless://{uuid}@{server}:{port}?{params}#{name}
```

---

## 操作命令指南

### 1. 删除指定版本的所有节点

**命令示例：**
```
删除V2的节点
```

**操作步骤：**
1. 在 xray-core config.json 中：
   - 删除所有 tag 包含 `v2-` 的 inbound 条目
   - 删除所有 tag 包含 `v2-` 的 outbound 条目
   - 删除所有 inboundTag 包含 `v2-` 的 routing rule
2. 在 haproxy.cfg 中：
   - 删除所有 `lb-*v2-*` 格式的 server 行

### 2. 替换指定版本的节点

**命令示例：**
```
帮我把V2替换掉，替换的节点信息如下：
ss://YWVzLTEyOC1nY206MWRmMzNhMTUtYmU3Ny00OGFkLWFhYzItODY3YTRmZGFiMjAw@server.com:49500#🇭🇰 官网
ss://YWVzLTEyOC1nY206MWRmMzNhMTUtYmU3Ny00OGFkLWFhYzItODY3YTRmZGFiMjAw@server.com:49501#🇭🇰 香港 01
ss://YWVzLTEyOC1nY206MWRmMzNhMTUtYmU3Ny00OGFkLWFhYzItODY3YTRmZGFiMjAw@server.com:49502#🇭🇰 香港 02
```

**操作步骤：**
1. 首先删除当前 V2 版本的所有节点（同上）
2. 解析提供的节点 URL：
   - 识别协议类型（ss/trojan/vmess/vless）
   - 解析节点参数（**直接解码 Base64，不要调用外部工具**）
   - 从节点名称识别地区
3. 为每个节点生成配置：
   - 分配端口（从 16801 开始递增）
   - 按地区分组并编号（如 hkv2-01, hkv2-02...）
   - 创建 inbound、outbound、routing rule
4. 更新 haproxy 配置：
   - 添加对应的 server 行

### 3. 添加新版本节点

**命令示例：**
```
添加V5版本的节点，端口范围使用 167XX，节点如下：
trojan://password@server.com:443#🇯🇵 日本 01
...
```

**操作步骤：**
1. 确定端口范围和命名规则
2. 解析节点 URL（**直接解码，不写脚本**）
3. 生成配置并添加到两个文件

---

## 修改规则（重要！）

### 编码风格要求（必须严格遵守！）

**xray-core config.json 中的 inbounds、outbounds、routing.rules 每个条目必须是单行压缩 JSON 格式！**

✅ 正确格式（单行压缩）：
```json
{"tag":"hkv1-01-in","port":10801,"listen":"127.0.0.1","protocol":"mixed","sniffing":{"enabled":false,"destOverride":["http","tls"],"routeOnly":false},"settings":{"auth":"noauth","udp":false,"allowTransparent":false}},
{"tag":"hkv1-02-in","port":10802,"listen":"127.0.0.1","protocol":"mixed","sniffing":{"enabled":false,"destOverride":["http","tls"],"routeOnly":false},"settings":{"auth":"noauth","udp":false,"allowTransparent":false}},
```

❌ 错误格式（多行展开）：
```json
{
  "tag": "hkv1-01-in",
  "port": 10801,
  "listen": "127.0.0.1",
  ...
}
```

**注意：**
- 每个 inbound/outbound/routing rule 条目独占一行
- 条目之间用逗号分隔，最后一个条目后无逗号
- 不要在 JSON 键值对之间添加多余的空格（如 `"tag":"value"` 而非 `"tag": "value"`）

### 必须遵守的规则

1. **只修改指定版本的节点，不动其他版本**
   - 如果说"修改V2"，只操作 168XX 端口和 v2 标签的节点
   - 其他版本的配置必须完全保留

2. **保持代码风格一致**
   - xray-core JSON 使用单行压缩格式
   - haproxy 节点紧凑排列，不添加地区注释

3. **端口分配规则**
   - 同一地区的节点端口必须连续
   - 不同地区按照预设顺序分配（通常：HK→TW→SG→JP→US→其他）
   - 每个版本的起始端口固定不变

4. **Tag 命名必须一致（所有版本统一格式）**
   - xray-core inbound tag: `{region}v{version}-{num}-in` (如 `hkv1-01-in`, `hkv2-01-in`)
   - xray-core outbound tag: `{region}v{version}-{num}` (如 `hkv1-01`, `hkv2-01`)
   - haproxy server name: `lb-{region}v{version}-{num}` (如 `lb-hkv1-01`, `lb-hkv2-01`)
   - 编号始终为两位数：01, 02, ..., 10, 11...

5. **完整性检查**
   - 每个节点必须同时有 inbound、outbound、routing rule
   - haproxy 中的每个 server 必须对应 xray-core 中的一个节点

---

## 常见地区排序（推荐）

配置节点时建议按以下顺序排列：
1. 香港 (HK)
2. 台湾 (TW)
3. 新加坡 (SG)
4. 日本 (JP)
5. 韩国 (KR)
6. 美国 (US)
7. 其他亚洲国家（澳门、印度等）
8. 欧洲国家（英国、德国等）
9. 大洋洲（澳大利亚等）
10. 其他地区

---

## 示例：完整的 V3 节点替换流程

**输入：**
```
帮我把V3替换掉，节点如下：
ss://YWVz...@server1.com:443#🇭🇰 香港 01
ss://YWVz...@server2.com:443#🇭🇰 香港 02
ss://YWVz...@server3.com:443#🇯🇵 日本 01
```

**处理过程：**

1. 删除现有 V3 节点（166XX 端口）

2. **直接解析**节点（不写脚本！）：
   - 节点1: HK, port 16601, tag hkv3-01
   - 节点2: HK, port 16602, tag hkv3-02
   - 节点3: JP, port 16603, tag jpv3-01

3. 生成 xray-core inbounds（单行压缩格式）:
```json
{"tag":"hkv3-01-in","port":16601,"listen":"127.0.0.1","protocol":"mixed","sniffing":{"enabled":false,"destOverride":["http","tls"],"routeOnly":false},"settings":{"auth":"noauth","udp":false,"allowTransparent":false}},
{"tag":"hkv3-02-in","port":16602,"listen":"127.0.0.1","protocol":"mixed","sniffing":{"enabled":false,"destOverride":["http","tls"],"routeOnly":false},"settings":{"auth":"noauth","udp":false,"allowTransparent":false}},
{"tag":"jpv3-01-in","port":16603,"listen":"127.0.0.1","protocol":"mixed","sniffing":{"enabled":false,"destOverride":["http","tls"],"routeOnly":false},"settings":{"auth":"noauth","udp":false,"allowTransparent":false}},
```

4. 生成 xray-core outbounds（单行压缩格式）:
```json
{"tag":"hkv3-01","protocol":"shadowsocks","settings":{"servers":[{"address":"server1.com","port":443,"method":"aes-128-gcm","password":"解码后的密码","level":1}]},"mux":{"enabled":false,"concurrency":-1}},
{"tag":"hkv3-02","protocol":"shadowsocks","settings":{"servers":[{"address":"server2.com","port":443,"method":"aes-128-gcm","password":"解码后的密码","level":1}]},"mux":{"enabled":false,"concurrency":-1}},
{"tag":"jpv3-01","protocol":"shadowsocks","settings":{"servers":[{"address":"server3.com","port":443,"method":"aes-128-gcm","password":"解码后的密码","level":1}]},"mux":{"enabled":false,"concurrency":-1}},
```

5. 生成 routing rules（单行压缩格式）:
```json
{"type":"field","inboundTag":["hkv3-01-in"],"outboundTag":"hkv3-01"},
{"type":"field","inboundTag":["hkv3-02-in"],"outboundTag":"hkv3-02"},
{"type":"field","inboundTag":["jpv3-01-in"],"outboundTag":"jpv3-01"},
```

6. 生成 haproxy servers（紧凑排列，无注释）:
```
    server lb-hkv3-01 host.docker.internal:16601 weight 100
    server lb-hkv3-02 host.docker.internal:16602 weight 100
    server lb-jpv3-01 host.docker.internal:16603 weight 100
```

---

## 文件编辑注意事项

### xray-core config.json
- 使用 JSON 格式，注意逗号分隔
- inbounds、outbounds、routing.rules 都是数组
- 保持现有的压缩格式（单行 JSON 对象）

### haproxy.cfg
- 使用空格缩进（4个空格）
- server 行格式严格：`server {name} {address}:{port} weight 100`
- 节点紧凑排列，不添加地区注释
- 不同版本的节点可以连续排列

---

## 快速命令参考

| 命令 | 说明 |
|------|------|
| `删除V{n}的节点` | 删除指定版本所有节点 |
| `替换V{n}的节点` | 替换指定版本节点（需提供新节点列表） |
| `添加节点到V{n}` | 向指定版本追加节点 |
| `添加新版本V{n}，端口范围{XXXXX}` | 创建新版本（如 v5），需指定端口起始范围 |
| `查看V{n}的节点列表` | 显示指定版本的所有节点 |
| `检查配置一致性` | 验证 xray-core 和 haproxy 配置是否同步 |

### 添加新版本示例
```
添加新版本V5，端口范围16701开始，节点如下：
ss://...@server.com:443#🇭🇰 香港 01
ss://...@server.com:443#🇭🇰 香港 02
trojan://...@server.com:443#🇯🇵 日本 01
```

AI 会：
1. 为 v5 分配端口从 16701 开始
2. 生成 hkv5-01, hkv5-02, jpv5-01 等节点
3. 直接更新两个配置文件（不写任何脚本）

---

## 协议自动识别

AI 应能自动识别以下协议格式并正确解析：

- `ss://...` → Shadowsocks
- `trojan://...` → Trojan
- `vmess://...` → VMess (Base64 编码的 JSON)
- `vless://...` → VLESS
- `ssr://...` → ShadowsocksR
- `hysteria://...` → Hysteria
- `hysteria2://...` → Hysteria2
- `tuic://...` → TUIC

对于不熟悉的协议，应先解析 URL 结构，参考 xray-core 文档生成对应配置。

---

## 错误处理

1. 如果节点 URL 无法解析，跳过该节点并报告
2. 如果地区无法识别，使用 `unknown` 作为地区代码
3. 如果端口冲突，报告错误并终止操作
4. 修改完成后提示用户检查并重启服务

---

*最后更新: 2024*