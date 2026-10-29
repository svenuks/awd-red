---
name: awd-asset
description: AWD 资产统一数据库管理 (awd.db) 与后台 5 秒异步探活看门狗，自拉起单页全景 WebUI (127.0.0.1:8090)。
---

# AWD 资产管理与全景大盘 (awd-asset)

统一数据库管理（SQLite `awd.db`）与后台异步探活看门狗。**任何时候调用资产技能，后台均自动保障拉起极简实时 Web UI 态势大盘**。

> [!TIP]
> **AWD-Red 平台联动**：`awd_asset.py import` 或 `add` 录入对手资产后，会自动将对手目标同步输出至 **AWD-Red 平台配置**（`config/targets.txt`），并调用 HTTP API (`http://127.0.0.1:8800/api/targets`) 实时激活新平台目标！

---

## 🌐 实时 Web UI 全景大盘 (一页揽全局)

- **访问地址**：[http://127.0.0.1:8090](http://127.0.0.1:8090)（严格监听本地回环，安全隔离）
- **单页集成板块**：
  1. **顶部态势卡**：实时存活靶机率（动态呼吸灯）、已挖漏洞数、收获 Flag 战果、探活守护状态；
  2. **🎯 目标靶机态势 (Targets)**：支持一键过滤（仅存活对手 / 全部 / 我方），点击直接跳转 Web 端口；
  3. **🔍 发现漏洞清单 (Vulns)**：按题型展示已审计出的漏洞文件、行号、类型及 PoC 模板；
  4. **🏁 Flag 战果榜 (Flags)**：目标 IP、捕获 Flag 值与裁判机判定（成功/重复/失败）；
- **动态无感刷新**：前端每 2.5 秒通过 `/api/status` 自动局部热更新，无需手工刷新网页。

### Web UI 守护管理
```bash
# 手动打开/重启 Web UI
python3 scripts/awd_asset.py ui [--port 8090]

# 停止后台 Web UI 服务
python3 scripts/awd_asset.py ui-stop
```
*(日常无需手动敲命令启动，任何资产操作如 import、query、start 均会自动静默自愈拉起 Web UI)*

---

## 命令行一键按类查询 (`query`)

```bash
# 1. 直接查具体题型 (默认仅输出存活的对手靶机)
python3 scripts/awd_asset.py query seacms

# 2. 仅提取存活对手 URL (供攻击打靶脚本直接消费)
python3 scripts/awd_asset.py query seacms --urls

# 3. 查我方防守机
python3 scripts/awd_asset.py query self

# 4. 查挖掘出的漏洞
python3 scripts/awd_asset.py query vulns [seacms]

# 5. 查 Flag 战果
python3 scripts/awd_asset.py query flags

# 6. 查全场题型大盘
python3 scripts/awd_asset.py query apps
```

---

## 资产维护与探活看门狗

```bash
# 录入单个资产 (支持参数化配置我方防守机及 SSH 账号密码)
python3 scripts/awd_asset.py add 192.168.1.50 --port 80 --self --ssh-port 22 --ssh-user ctf --ssh-pass "xxx"
python3 scripts/awd_asset.py add 192.168.1.101 --port 80 --role opponent

# 批量导入资产
python3 scripts/awd_asset.py import targets.txt [--my-ip 192.168.1.50]

# 设置/查询比赛配置 (Flag Server / Token)
python3 scripts/awd_asset.py config flag_server "http://10.0.0.1/get_flag?token=xxx"
python3 scripts/awd_asset.py config flag_server

# 启动 5s 异步探活看门狗 (后台常驻)
python3 scripts/awd_asset.py start --interval 5

# 终端查看实时存活看板
python3 scripts/awd_asset.py status

# 停止后台看门狗
python3 scripts/awd_asset.py stop
```
