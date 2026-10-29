---
name: awd-addflag
description: AWD 外部 Flag 录入与自动提交工具：提供 CLI 命令行、管道输入正则提取、批量入库及主动通知平台提交裁判机功能。支持外部脚本、人工取旗结果或旁路工具将 Flag 快速录入 AWD-Red 平台数据库并触发提交。
---

# AWD Flag 录入与提交技能 (awd-addflag)

本技能提供了一个标准化的 CLI 脚本及 Python 接口，用于让外部脚本、旁路探测工具、人工测试或反弹会话中的 Flag 快速安全地入库至 AWD-Red 平台（SQLite `flags` 表），并支持自动去重和即时触发裁判机提交。

---

## 1. 核心工具位置

- **CLI 脚本路径**：`tools/flag_cli.py` 或 `skills/awd-addflag/scripts/flag_cli.py`
- **数据库路径**：`data/platform.db`

---

## 2. 常用操作命令

### 2.1 直接录入单个或多个 Flag
```bash
# 录入单条 Flag，指定目标 IP 和来源脚本名
python3 tools/flag_cli.py add "flag{abcdef123456}" --ip 192.168.1.101 --source my_script

# 录入并立即通知平台向裁判机提交 (--submit)
python3 tools/flag_cli.py add "flag{test_flag_01}" --ip 192.168.1.101 --submit
```

### 2.2 管道模式 (标准输入正则提取)
从 HTTP 响应、日志文件或终端输出中自动提取符合规则的 Flag 并录入：
```bash
# 从命令输出中提取
curl -s http://192.168.1.101/curl.php -d "c=cat+/flag" | python3 tools/flag_cli.py pipe --ip 192.168.1.101 --submit

# 从文本文件或日志中提取
cat response.log | python3 tools/flag_cli.py pipe --source log_parser
```

### 2.3 查看最近的 Flag 记录
```bash
python3 tools/flag_cli.py list -n 20
```

### 2.4 手动触发平台提交所有 pending/failed Flag
```bash
python3 tools/flag_cli.py submit
```

---

## 3. 在外部 Python 脚本中集成

### 方式一：子进程调用 CLI（跨项目/解耦推荐）
```python
import subprocess
import shutil

def record_flag(flag: str, ip: str, source: str = "custom_tool", submit_now: bool = True):
    cmd = [
        "python3", "tools/flag_cli.py",
        "add", flag,
        "--ip", ip,
        "--source", source
    ]
    if submit_now:
        cmd.append("--submit")
    subprocess.run(cmd, check=True)
```

### 方式二：Python 直接导入模块
```python
import sys
import os
from pathlib import Path

BASE_DIR = Path(os.environ.get("AWD_RED_DIR", ".")).resolve()
sys.path.insert(0, str(BASE_DIR))

from core.db import Database

# 返回 True 表示新 Flag 成功入库，False 表示重复已被过滤
is_new = Database.save_flag(
    flag_val="flag{xxxxx}",
    round_num=0,
    poc_name="my_script",
    target_ip="192.168.1.101"
)
```
