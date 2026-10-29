#!/usr/bin/env python3
"""
AWD-Red Flag CLI Tool
用于在外部脚本、管道或命令行中录入、查询与提交 Flag。

支持使用方式:
1. 参数传参:
   python3 tools/flag_cli.py add "flag{xxx}" --ip 192.168.1.101 --source test_poc
2. 管道/标准输入 (自动正则提取并录入):
   cat response.txt | python3 tools/flag_cli.py pipe --ip 192.168.1.101
   curl -s http://192.168.1.101/shell.php | python3 tools/flag_cli.py pipe
3. 查看最近 Flags:
   python3 tools/flag_cli.py list
4. 触发立即向裁判机提交 pending 状态的 flag:
   python3 tools/flag_cli.py submit
"""

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import urllib.request
from pathlib import Path

# 寻找 awd-red 目录
def find_awd_red_dir() -> Path:
    # 尝试向上寻找
    cur = Path(__file__).resolve().parent
    for _ in range(5):
        if (cur / "awd-red" / "data" / "platform.db").exists():
            return cur / "awd-red"
        if (cur / "data" / "platform.db").exists() and cur.name == "awd-red":
            return cur
        cur = cur.parent
    # 兜底当前工程目录
    return Path(__file__).resolve().parent.parent

BASE_DIR = find_awd_red_dir()
DB_PATH = BASE_DIR / "data" / "platform.db"
CONFIG_PATH = BASE_DIR / "config" / "settings.json"

DEFAULT_FLAG_REGEX = r'(?:flag|FLAG)\{[a-zA-Z0-9_\-+=/]{6,128}\}'

def get_db_connection():
    if not DB_PATH.exists():
        # 如果数据库不存在，尝试触发初始化
        sys.path.insert(0, str(BASE_DIR))
        try:
            from core.db import Database
            Database.init_db()
        except Exception:
            pass
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def load_flag_regex() -> str:
    """从 settings.json 读取配置的正则，默认回退 DEFAULT_FLAG_REGEX"""
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                return cfg.get("attack", {}).get("flag_regex") or DEFAULT_FLAG_REGEX
        except Exception:
            pass
    return DEFAULT_FLAG_REGEX

def save_single_flag(flag_val: str, target_ip: str = "127.0.0.1", source: str = "cli", round_num: int = 0) -> bool:
    """插入单条 Flag，根据 SHA-256 去重"""
    flag_clean = flag_val.strip()
    if not flag_clean:
        return False
    flag_hash = hashlib.sha256(flag_clean.encode("utf-8")).hexdigest()
    
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO flags (flag_hash, flag_val, round_num, poc_name, target_ip, submit_status)
                VALUES (?, ?, ?, ?, ?, 'pending')
                """,
                (flag_hash, flag_clean, round_num, source, target_ip)
            )
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def trigger_platform_resubmit() -> bool:
    """尝试通过平台的本地 API 触发立即提交"""
    try:
        url = "http://127.0.0.1:8800/api/flags/resubmit"
        req = urllib.request.Request(url, data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except Exception:
        return False

# ==================== CLI 命令处理器 ====================

def cmd_add(args):
    """直接添加 Flag"""
    flags_to_add = args.flags
    ip = args.ip or "127.0.0.1"
    source = args.source or "cli"
    round_num = args.round or 0

    added_count = 0
    dup_count = 0

    for f in flags_to_add:
        if save_single_flag(f, target_ip=ip, source=source, round_num=round_num):
            print(f"[+] 录入成功: {f}")
            added_count += 1
        else:
            print(f"[-] Flag 已存在(跳过): {f}")
            dup_count += 1

    if args.submit and added_count > 0:
        print("[*] 触发平台立即提交 Flag...")
        if trigger_platform_resubmit():
            print("[+] 提交请求已发送至后台调度器")
        else:
            print("[-] 后台平台可能未运行，Flag 将在下次轮询时自动提交")

    print(f"\n统计: 新增 {added_count} 个, 重复 {dup_count} 个")

def cmd_pipe(args):
    """从 stdin 提取文本中的 Flag 并批量录入"""
    content = sys.stdin.read()
    if not content:
        print("[-] 管道中没有读取到内容")
        return

    pattern = load_flag_regex()
    matches = re.findall(pattern, content)

    if not matches:
        # 尝试备用兜底正则
        matches = re.findall(DEFAULT_FLAG_REGEX, content)

    if not matches:
        print("[-] 未在输入内容中匹配到符合规范的 Flag")
        return

    # 去重
    unique_flags = list(dict.fromkeys(matches))
    ip = args.ip or "127.0.0.1"
    source = args.source or "pipe"

    added_count = 0
    for f in unique_flags:
        if save_single_flag(f, target_ip=ip, source=source):
            print(f"[+] 提取并录入: {f}")
            added_count += 1
        else:
            print(f"[-] 已存在(跳过): {f}")

    if args.submit and added_count > 0:
        trigger_platform_resubmit()

    print(f"\n提取完成: 共提取 {len(unique_flags)} 个, 新增 {added_count} 个")

def cmd_list(args):
    """查询最近的 Flag"""
    conn = get_db_connection()
    cursor = conn.cursor()
    limit = args.limit or 20
    cursor.execute(
        "SELECT flag_val, target_ip, poc_name, submit_status, found_at FROM flags ORDER BY found_at DESC LIMIT ?",
        (limit,)
    )
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print("[*] 暂无 Flag 记录")
        return

    print(f"\n{'Flag':<42} | {'目标IP':<15} | {'状态':<10} | {'来源':<15} | {'发现时间'}")
    print("-" * 105)
    for r in rows:
        print(f"{r['flag_val']:<42} | {r['target_ip']:<15} | {r['submit_status']:<10} | {r['poc_name']:<15} | {r['found_at']}")
    print(f"\n总计显示最近 {len(rows)} 条")

def cmd_submit(args):
    """手动触发提交"""
    print("[*] 正在通知平台提交 pending/failed Flag...")
    if trigger_platform_resubmit():
        print("[+] 触发成功，平台正在异步提交")
    else:
        print("[-] 平台 API 无法连接 (http://127.0.0.1:8800)，请确保平台已启动: ./start.sh")

def main():
    parser = argparse.ArgumentParser(description="AWD-Red Flag 管理 CLI 工具")
    subparsers = parser.add_subparsers(dest="subcommand", help="子命令")

    # add
    p_add = subparsers.add_parser("add", help="手动添加一个或多个 Flag")
    p_add.add_argument("flags", nargs="+", help="Flag 字符串")
    p_add.add_argument("--ip", default="127.0.0.1", help="目标 IP")
    p_add.add_argument("--source", "-s", default="cli", help="来源名称/脚本名")
    p_add.add_argument("--round", "-r", type=int, default=0, help="轮次编号")
    p_add.add_argument("--submit", action="store_true", help="录入后立即触发平台提交")
    p_add.set_defaults(func=cmd_add)

    # pipe
    p_pipe = subparsers.add_parser("pipe", help="从标准输入(管道)中正则提取 Flag 并录入")
    p_pipe.add_argument("--ip", default="127.0.0.1", help="目标 IP")
    p_pipe.add_argument("--source", "-s", default="pipe", help="来源名称/脚本名")
    p_pipe.add_argument("--submit", action="store_true", help="录入后立即触发平台提交")
    p_pipe.set_defaults(func=cmd_pipe)

    # list
    p_list = subparsers.add_parser("list", help="查看最近的 Flag 记录")
    p_list.add_argument("-n", "--limit", type=int, default=20, help="显示数量 (默认 20)")
    p_list.set_defaults(func=cmd_list)

    # submit
    p_sub = subparsers.add_parser("submit", help="触发向裁判机提交待处理的 Flag")
    p_sub.set_defaults(func=cmd_submit)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
