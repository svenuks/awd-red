---
name: awd-vulscan
description: AWD 自机源码免密拉取、D盾 深度漏洞审计与自动录入 AWD-Red 漏洞库技能
---

# AWD 源码拉取与漏洞审计 (awd-vulscan)

自动从自机免密同步拉取 Web 源码，无缝衔接内嵌 D盾 引擎深度审计，提取可疑暗桩、代码执行点与后门入参，并进行存活探活，**全量实时录入 AWD-Red 新平台漏洞库**。

---

## 🎯 漏洞库新平台联动机制

1. **自动录入新平台**：
   - 脚本扫描出的高危后门与漏洞（默认过滤 Level >= 3），会自动持久化写入新平台数据库：  
     `data/platform.db` 中的 `vulns` 表；
   - 若 AWD-Red 平台处于启动状态，脚本还会通过 HTTP API (`http://127.0.0.1:8800/api/vulns`) 进行实时热推送。

2. **新平台查看入口**：
   - 打开 AWD-Red 控制台：**[http://localhost:8800](http://localhost:8800)**；
   - 点击顶部导航标签页：**`🔍 漏洞库中心 (Vulnerability Hub)`**；
   - 控制台实时展示：
     - **探活状态**：标记 `🟢 已存活` 或 `⚪ 未探活`；
     - **严重等级**：Level 5 / 4 / 3 严重程度标签；
     - **利用点位置**：具体文件名与代码行号（如 `/curl.php:3`）；
     - **触发入参**：如 `POST:1`, `GET:cmd`；
     - **利用载荷**：提供一键复制 Payload 按钮，直接用于指导编写 PoC 或手动拿 Flag！

---

## ⚡ 一键极速调用命令

### 1. 提供 SSH 密码极速拉取源码 + 自动审计 + 录入漏洞库（推荐首选）
```bash
python3 ~/.agents/skills/awd-vulscan/scripts/awd_vulscan.py --host <自机IP> --ssh-port 22 --user ctf --pass "<SSH密码>"
```

### 2. 已配置 SSH 私钥免密或已录入平台
```bash
python3 ~/.agents/skills/awd-vulscan/scripts/awd_vulscan.py
```

### 3. 针对本地已有源码目录直接审计
```bash
python3 skills/awd-vulscan/scripts/awd_vulscan.py ./awd_backups/192.168.1.101/html
```

### 4. 常用参数
- `--host`：自机/靶机 IP 地址
- `--ssh-port`：SSH 端口（默认 22）
- `--user`：SSH 用户名（默认 `ctf`）
- `--pass` / `--password`：SSH 登录密码
- `--key`：SSH 私钥文件路径
- `[target]`：可选，手动指定本地源码目录或 `.tar.gz` 压缩包（跳过自动拉代码）
- `--clean`：写入新平台前清空旧漏洞记录（新一轮审计时推荐）
- `--no-verify`：跳过存活探活阶段，仅做静态扫描
- `--min-level [2|3|4|5]`：告警等级过滤（默认 3）
- `--json`：在终端以 JSON 格式打印结果

---

## 📋 执行流程

```
[自机免密 rsync 同步] 
       ↓
[D盾 深度特征扫描] (过滤 Level >= 3)
       ↓
[自机轻量级存活探活] (验证入参是否可触达)
       ↓
[全量落库 AWD-Red 新平台] ──> Web 控制台【🔍 漏洞库中心】实时查阅与复制 Payload
```
