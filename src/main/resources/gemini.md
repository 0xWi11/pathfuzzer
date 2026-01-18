# Proxy Node Configuration Management Guide

## 操作原则（AI 必读!）

> **在执行任何任务之前,必须遵守以下原则:**

### 1. 禁止过度工程化

- **不要为简单任务编写脚本文件**(.py / .sh / .js 等)
- 如果任务可以用 1-2 行命令完成,直接执行,不要创建脚本
- 如果数据量小(<100 条),直接处理比写自动化脚本更高效

### 2. **仅输出需要修改的部分**

- **不要输出完整的配置文件**
- **只告诉用户需要添加、修改、删除哪些具体的行**
- 提供精确的定位信息(如:在第X行之后添加、删除第Y-Z行、将第N行修改为...)
- 使用清晰的分隔符标记不同的修改操作

### 3. AI 可直接解码 Base64

- SS/SSR/VMess 链接中的 Base64 **你可以直接在脑中解码**,不需要调用任何外部工具
- 示例:`YWVzLTEyOC1nY206cGFzc3dvcmQ=` = `aes-128-gcm:password`
- **禁止**使用 `python -c "import base64..."` 或 `echo ... | base64 -d`

### 4. 正确的工作流程

```
❌ 错误做法:
1. 输出完整的 config20.json 文件
2. 输出完整的 haproxy.cfg 文件
3. 让用户完全替换文件

✅ 正确做法:
1. 直接阅读并理解节点 URL(包括 Base64 部分)
2. 分析需要修改的具体位置
3. 输出格式化的增量修改指令,包含:
   - 需要删除的行(提供行号范围或匹配模式)
   - 需要添加的行(提供插入位置和完整内容)
   - 需要修改的行(提供原内容和新内容)
4. 用户根据指令手动修改配置文件
```

### 5. 修改指令输出格式

每次修改必须使用以下标准格式:

```markdown
## 文件: config20.json

### 操作 1: 删除 V2 版本的 inbound 配置
**位置:** 在 "inbounds" 数组中
**匹配模式:** 所有包含 `"tag":"hkv2-` 或 `"tag":"twv2-` 等 v2 标签的行
**操作:** 删除以下所有行(共约 XX 行):
- 删除所有 tag 包含 `v2-` 的 inbound 条目

### 操作 2: 添加新的 V2 inbound 配置
**位置:** 在 "inbounds" 数组末尾,最后一个 v1 节点之后
**操作:** 添加以下内容:
```json
{"tag":"hkv2-01-in","port":16801,"listen":"127.0.0.1","protocol":"mixed","sniffing":{"enabled":false,"destOverride":["http","tls"],"routeOnly":false},"settings":{"auth":"noauth","udp":false,"allowTransparent":false}},
{"tag":"hkv2-02-in","port":16802,"listen":"127.0.0.1","protocol":"mixed","sniffing":{"enabled":false,"destOverride":["http","tls"],"routeOnly":false},"settings":{"auth":"noauth","udp":false,"allowTransparent":false}}
```

### 操作 3: 删除 V2 版本的 outbound 配置
**位置:** 在 "outbounds" 数组中
**操作:** 删除所有 tag 包含 `v2-` 的 outbound 条目
```

---

## 项目概述

本项目用于管理多订阅源的代理节点配置,包含两个核心配置文件:
- `config20.json` - Xray-core 代理客户端配置
- `haproxy.cfg` - HAProxy 负载均衡配置

两个配置文件必须保持同步:当 xray-core 配置中添加/删除/修改节点时,haproxy 配置也需要相应更新。

---

## 版本标识系统

节点按订阅源分为多个版本,每个版本使用固定的端口范围:

### 已定义版本

| 版本 | 端口范围                | xray-core tag 格式 | haproxy server 格式 | 说明 |
|------|---------------------|-------------------|---------------------|------|
| v1   | 108XX (10801-10899) | `{region}v1-{num}` 如 `hkv1-01` | `lb-{region}v1-{num}` 如 `lb-hkv1-01` | 主订阅源 |
| v2   | 168XX (16801-16899) | `{region}v2-{num}` 如 `hkv2-01` | `lb-{region}v2-{num}` 如 `lb-hkv2-01` | 订阅源2 |
| v3   | 166XX (16601-16699) | `{region}v3-{num}` 如 `hkv3-01` | `lb-{region}v3-{num}` 如 `lb-hkv3-01` | 订阅源3 |
| v4   | 161XX (16101-16299) | `{region}v4-{num}` 如 `hkv4-01` | `lb-{region}v4-{num}` 如 `lb-hkv4-01` | 订阅源4 |
| v5   | 158XX (15801-15999) | `{region}v5-{num}` 如 `hkv5-01` | `lb-{region}v5-{num}` 如 `lb-hkv5-01` | 订阅源5 |

---

## 地区代码对照表

| 地区 | 代码 | 地区 | 代码 | 地区 | 代码 |
|------|------|------|------|------|------|
| 香港 | hk | 台湾 | tw | 新加坡 | sg |
| 日本 | jp | 美国 | us | 韩国 | kr |
| 英国 | uk | 德国 | de | 法国 | fr |
| 荷兰 | nl | 意大利 | it | 西班牙 | es |
| 加拿大 | ca | 澳大利亚 | au | 俄罗斯 | ru |

---

## xray-core 配置结构

### 每个节点需要配置的三个部分

#### 1. Inbound (入站配置) - 单行压缩 JSON
```json
{"tag":"{region}v{version}-{num}-in","port":{port},"listen":"127.0.0.1","protocol":"mixed","sniffing":{"enabled":false,"destOverride":["http","tls"],"routeOnly":false},"settings":{"auth":"noauth","udp":false,"allowTransparent":false}}
```

#### 2. Outbound (出站配置) - 单行压缩 JSON

**Trojan 协议:**
```json
{"tag":"{region}v{version}-{num}","protocol":"trojan","settings":{"servers":[{"address":"服务器地址","port":端口号,"password":"密码","level":1}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"allowInsecure":true,"serverName":"SNI域名"}},"mux":{"enabled":false,"concurrency":-1}}
```

**Shadowsocks 协议:**
```json
{"tag":"{region}v{version}-{num}","protocol":"shadowsocks","settings":{"servers":[{"address":"服务器地址","port":端口号,"method":"加密方式","password":"密码","level":1}]},"mux":{"enabled":false,"concurrency":-1}}
```

#### 3. Routing Rule (路由规则) - 单行压缩 JSON
```json
{"type":"field","inboundTag":["{region}v{version}-{num}-in"],"outboundTag":"{region}v{version}-{num}"}
```

---

## haproxy 配置结构

### 节点行格式
```
    server lb-{region}v{version}-{num} host.docker.internal:{port} weight 100
```

- **不要添加地区注释**
- **节点紧凑排列**,每行一个节点,行与行之间无空行

---

## 操作命令示例

### 1. 删除指定版本的所有节点

**命令:**
```
删除V2的节点
```

**AI 应输出的修改指令格式:**

```markdown
## 文件: config20.json

### 操作 1: 删除 V2 的 inbound 配置
**位置:** "inbounds" 数组中
**操作:** 删除所有 tag 匹配 `*v2-*-in` 模式的条目
**示例匹配:** `"tag":"hkv2-01-in"`, `"tag":"jpv2-01-in"`

### 操作 2: 删除 V2 的 outbound 配置  
**位置:** "outbounds" 数组中
**操作:** 删除所有 tag 匹配 `*v2-*` 模式的条目(不含 -in 后缀)
**示例匹配:** `"tag":"hkv2-01"`, `"tag":"jpv2-01"`

### 操作 3: 删除 V2 的 routing 规则
**位置:** "routing" -> "rules" 数组中
**操作:** 删除所有 inboundTag 或 outboundTag 包含 `v2-` 的规则

## 文件: haproxy.cfg

### 操作 4: 删除 V2 的 server 行
**位置:** `backend proxy_back_vx` 部分
**操作:** 删除所有匹配 `server lb-*v2-*` 的行
**示例匹配:** `server lb-hkv2-01 ...`, `server lb-jpv2-01 ...`
```

### 2. 替换指定版本的节点

**命令:**
```
帮我把V2替换掉,节点如下:
ss://YWVzLTEyOC1nY206MTIzNDU2@example.com:443#🇭🇰 香港 01
ss://YWVzLTEyOC1nY206MTIzNDU2@example.com:444#🇯🇵 日本 01
```

**AI 应输出:**

```markdown
## 步骤 1: 删除现有 V2 节点
(参考"删除指定版本"的操作)

## 步骤 2: 添加新节点

### 文件: config20.json

#### 在 "inbounds" 数组中添加
**位置:** 最后一个 v1 inbound 之后,第一个 v3 inbound 之前(如果没有 v3,则在 v1 之后)
**添加内容:**
```json
{"tag":"hkv2-01-in","port":16801,"listen":"127.0.0.1","protocol":"mixed","sniffing":{"enabled":false,"destOverride":["http","tls"],"routeOnly":false},"settings":{"auth":"noauth","udp":false,"allowTransparent":false}},
{"tag":"jpv2-01-in","port":16802,"listen":"127.0.0.1","protocol":"mixed","sniffing":{"enabled":false,"destOverride":["http","tls"],"routeOnly":false},"settings":{"auth":"noauth","udp":false,"allowTransparent":false}}
```

#### 在 "outbounds" 数组中添加
**位置:** 在 direct 和 block 之前
**添加内容:**
```json
{"tag":"hkv2-01","protocol":"shadowsocks","settings":{"servers":[{"address":"example.com","port":443,"method":"aes-128-gcm","password":"123456","level":1}]},"mux":{"enabled":false,"concurrency":-1}},
{"tag":"jpv2-01","protocol":"shadowsocks","settings":{"servers":[{"address":"example.com","port":444,"method":"aes-128-gcm","password":"123456","level":1}]},"mux":{"enabled":false,"concurrency":-1}}
```

#### 在 "routing" -> "rules" 数组中添加
**位置:** 在现有路由规则末尾,direct 规则之前
**添加内容:**
```json
{"type":"field","inboundTag":["hkv2-01-in"],"outboundTag":"hkv2-01"},
{"type":"field","inboundTag":["jpv2-01-in"],"outboundTag":"jpv2-01"}
```

### 文件: haproxy.cfg

#### 在 backend proxy_back_vx 中添加
**位置:** v2 节点区域(在 v1 节点之后,v3 节点之前)
**添加内容:**
```
    server lb-hkv2-01 host.docker.internal:16801 weight 100
    server lb-jpv2-01 host.docker.internal:16802 weight 100
```
```

---

## 输出格式要求（重要!）

### ✅ 正确的输出示例:

```markdown
## 修改摘要
- 删除 V3 的所有节点(共 30 个节点)
- 添加 V3 的新节点(共 5 个节点)

---

## 文件 1: config20.json

### 操作 1: 删除旧的 V3 inbound 配置
**定位方法:** 在 "inbounds" 数组中查找
**删除规则:** 删除所有 `"tag"` 字段匹配 `*v3-*-in` 的 JSON 对象
**受影响行数:** 约 30 行

### 操作 2: 添加新的 V3 inbound 配置  
**插入位置:** 在最后一个 v2 inbound 之后
**添加内容:**
```json
{"tag":"hkv3-01-in","port":16601,"listen":"127.0.0.1","protocol":"mixed",...},
{"tag":"hkv3-02-in","port":16602,"listen":"127.0.0.1","protocol":"mixed",...}
```
**注意:** 每行末尾需要逗号,最后一行除外

---

## 文件 2: haproxy.cfg

### 操作 3: 删除旧的 V3 server 配置
**定位方法:** 在 `backend proxy_back_vx` 部分
**删除规则:** 删除所有以 `server lb-*v3-` 开头的行
**受影响行数:** 约 30 行

### 操作 4: 添加新的 V3 server 配置
**插入位置:** 在 v2 server 之后,v4 server 之前(如果没有 v4,则在 v2 之后)
**添加内容:**
```
    server lb-hkv3-01 host.docker.internal:16601 weight 100
    server lb-hkv3-02 host.docker.internal:16602 weight 100
```
```

### ❌ 错误的输出(不要这样做):

```markdown
# 这是完整的 config20.json 文件:
{
  "log": {...},
  "dns": {...},
  "inbounds": [
    ... (完整的 5000 行配置)
  ]
}

# 这是完整的 haproxy.cfg 文件:
global
    ...
    (完整的 500 行配置)
```

---

## 必须遵守的规则

1. **只修改指定版本的节点,不动其他版本**
2. **保持代码风格一致** - xray-core JSON 使用单行压缩格式
3. **端口分配规则** - 同一地区的节点端口必须连续
4. **Tag 命名必须一致** - 格式: `{region}v{version}-{num}`
5. **完整性检查** - 每个节点必须同时有 inbound、outbound、routing rule

---

## 常见协议 URL 解析

### Shadowsocks (ss://)
```
ss://{base64(method:password)}@{server}:{port}#{name}
```

### Trojan (trojan://)
```
trojan://{password}@{server}:{port}?{params}#{name}
```

### VMess (vmess://)
```
vmess://{base64(json_config)}
```

---

*最后更新: 2025 - 增量修改版*