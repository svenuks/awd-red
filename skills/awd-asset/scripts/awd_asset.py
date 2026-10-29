#!/usr/bin/env python3
"""
AWD 统一资产与状态管理工具 (awd-asset)
支持:
  1. 资产文本极简导入 -> 写入统一 SQLite 数据库 (awd.db)
  2. 后台异步守护进程 -> 每 5 秒轮询并发探活，失效立即更新数据库 status
  3. 攻击端极速查询 -> 实时提取当前存活对手的目标 URL
"""

import os
import sys
import time
import signal
import sqlite3
import argparse
import asyncio
import json
import http.server
import urllib.parse
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = SKILL_DIR / "data"
DB_PATH = DATA_DIR / "awd.db"

def find_awd_red_dir():
    if os.environ.get("AWD_RED_DIR"):
        return Path(os.environ["AWD_RED_DIR"]).resolve()
    bundle_root = Path(__file__).resolve().parent.parent.parent.parent
    if (bundle_root / "core" / "db.py").exists():
        return bundle_root
    cur = Path.cwd()
    for _ in range(4):
        if (cur / "core" / "db.py").exists():
            return cur
        cur = cur.parent
    return Path.home() / "awd-red"

AWD_RED_DIR = find_awd_red_dir()

# 若 DB_PATH 是软链接，自动对齐到统一的实际数据目录，确保 PID 看门狗与日志唯一共享
REAL_DATA_DIR = DB_PATH.resolve().parent if DB_PATH.is_symlink() else DATA_DIR
PID_FILE = REAL_DATA_DIR / "daemon.pid"
LOG_FILE = REAL_DATA_DIR / "daemon.log"
UI_PID_FILE = REAL_DATA_DIR / "webui.pid"
UI_LOG_FILE = REAL_DATA_DIR / "webui.log"
UI_PORT = 8090


def get_db_connection(db_path=DB_PATH):
    """获取数据库连接并自动开启 WAL 模式以支持高并发读写"""
    os.makedirs(db_path.parent, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=10.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.row_factory = sqlite3.Row
    return conn


def init_database(db_path=DB_PATH):
    """初始化统一数据库 schema (targets, backdoors, vulns, flags)"""
    conn = get_db_connection(db_path)
    cur = conn.cursor()

    # 1. 资产表 (由 awd-asset 维护)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        app TEXT NOT NULL,
        ip TEXT NOT NULL,
        port INTEGER DEFAULT 80,
        role TEXT DEFAULT 'opponent',
        target_url TEXT NOT NULL,
        ssh_port INTEGER DEFAULT 22,
        ssh_user TEXT DEFAULT 'ctf',
        ssh_pass TEXT,
        ssh_key TEXT,
        status TEXT DEFAULT 'unknown',
        last_seen TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(app, ip, port)
    );
    """)

    # 动态迁移检查 (确保旧库平滑具备 SSH 凭据字段)
    for col, col_def in [
        ("ssh_port", "INTEGER DEFAULT 22"),
        ("ssh_user", "TEXT DEFAULT 'ctf'"),
        ("ssh_pass", "TEXT"),
        ("ssh_key", "TEXT")
    ]:
        try:
            cur.execute(f"ALTER TABLE targets ADD COLUMN {col} {col_def};")
        except Exception:
            pass

    # 2. 后门表 (独立存放预置暗桩、一句话木马、不死马)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS backdoors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        app TEXT NOT NULL,
        file TEXT NOT NULL,
        password TEXT NOT NULL,
        method TEXT DEFAULT 'POST',
        shell_type TEXT DEFAULT 'eval',
        sample_payload TEXT,
        defense_action TEXT DEFAULT 'delete',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 2.1 脚本与 WebShell 资产表 (由 awd-backdoor / awd-vuln 录入及探活)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS shell (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        app TEXT NOT NULL,
        file TEXT NOT NULL,
        password TEXT NOT NULL,
        method TEXT DEFAULT 'POST',
        shell_type TEXT DEFAULT 'eval',
        sample_payload TEXT,
        defense_action TEXT DEFAULT 'delete',
        flag_cmd TEXT,
        is_alive INTEGER DEFAULT 0,
        last_check TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    for col, col_def in [
        ("flag_cmd", "TEXT"),
        ("is_alive", "INTEGER DEFAULT 0"),
        ("last_check", "TIMESTAMP")
    ]:
        try:
            cur.execute(f"ALTER TABLE shell ADD COLUMN {col} {col_def};")
        except Exception:
            pass

    # 3. 漏洞表 (独立存放业务逻辑漏洞、命令注入、LFI、反序列化等代码缺陷)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS vulns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        app TEXT NOT NULL,
        file TEXT NOT NULL,
        line INTEGER,
        vuln_type TEXT NOT NULL,
        param TEXT,
        poc_template TEXT,
        patch_solution TEXT,
        verified INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    try:
        cur.execute("ALTER TABLE vulns ADD COLUMN verified INTEGER DEFAULT 0;")
    except Exception:
        pass

    # 4. 战果与 Flag 记录表
    cur.execute("""
    CREATE TABLE IF NOT EXISTS flags (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        round INTEGER DEFAULT 1,
        app TEXT NOT NULL,
        target_ip TEXT NOT NULL,
        flag TEXT NOT NULL,
        submit_status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 5. 比赛配置表 (存放 flag_server, token 等全局参数)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS config (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    conn.commit()
    conn.close()


def parse_ip_port(raw_ip, default_port=80):
    """鲁棒解析各种格式的 IP/Host 字符串，规避 :80:80 等重复端口问题"""
    raw_ip = str(raw_ip).strip()
    if raw_ip.startswith("http://"):
        raw_ip = raw_ip[7:]
    elif raw_ip.startswith("https://"):
        raw_ip = raw_ip[8:]
    raw_ip = raw_ip.rstrip("/")
    if ":" in raw_ip:
        parts = raw_ip.split(":", 1)
        try:
            return parts[0].strip(), int(parts[1].strip())
        except ValueError:
            return parts[0].strip(), int(default_port)
    return raw_ip, int(default_port)


def import_assets_text(text_content, my_ips=None, default_port=80, role_default="opponent", db_path=DB_PATH):
    """解析比赛原始分发文本并导入 targets 表"""
    init_database(db_path)
    conn = get_db_connection(db_path)
    cur = conn.cursor()

    # 查询已有我方资产 IP 集合以进行防误覆保护
    cur.execute("SELECT ip FROM targets WHERE role = 'self'")
    existing_self_ips = {r[0] for r in cur.fetchall()}

    my_ips = set(my_ips or []).union(existing_self_ips)
    lines = [line.strip() for line in text_content.splitlines()]

    current_app = "web"
    current_port = default_port
    inserted_count = 0

    for line in lines:
        if not line:
            continue

        # 检查是否为题型定义行 (例如: seacms 或 seacms:8080)
        if not line.replace(".", "").isdigit() and not ":" in line:
            current_app = line.strip()
            current_port = default_port
            continue
        elif ":" in line and not line.split(":")[0].replace(".", "").isdigit():
            parts = line.split(":", 1)
            current_app = parts[0].strip()
            try:
                current_port = int(parts[1].strip())
            except ValueError:
                current_port = default_port
            continue

        # IP 目标行 (支持 192.168.1.101 或 192.168.1.101:80)
        clean_ip, port = parse_ip_port(line, default_port=current_port)
        target_role = "self" if clean_ip in my_ips else role_default
        target_url = f"http://{clean_ip}/" if port == 80 else f"http://{clean_ip}:{port}/"

        cur.execute("""
        INSERT INTO targets (app, ip, port, role, target_url, status)
        VALUES (?, ?, ?, ?, ?, 'unknown')
        ON CONFLICT(app, ip, port) DO UPDATE SET
            role=CASE WHEN targets.role = 'self' THEN 'self' ELSE excluded.role END,
            target_url=excluded.target_url;
        """, (current_app, clean_ip, port, target_role, target_url))
        inserted_count += 1

    conn.commit()
    conn.close()
    return inserted_count


AWD_RED_TARGETS_TXT = AWD_RED_DIR / "config" / "targets.txt"
AWD_RED_API_TARGETS = "http://127.0.0.1:8800/api/targets"

def sync_to_awd_red(db_path=DB_PATH):
    """自动将 opponent 资产同步至 AWD-Red 平台 targets.txt 及 HTTP 接口"""
    try:
        conn = get_db_connection(db_path)
        cur = conn.cursor()
        cur.execute("SELECT ip FROM targets WHERE role = 'opponent' AND ip != '' GROUP BY ip ORDER BY ip ASC;")
        rows = cur.fetchall()
        conn.close()
        if not rows:
            return
        ips = [r["ip"] for r in rows]

        if AWD_RED_TARGETS_TXT.parent.exists():
            with open(AWD_RED_TARGETS_TXT, "w", encoding="utf-8") as f:
                f.write("# AWD 目标靶机 IPv4 列表 (从 awd-asset 自动同步)\n")
                for ip in ips:
                    f.write(f"{ip}\n")
            print(f"[+] 已自动同步 {len(ips)} 个目标资产至 AWD-Red: {AWD_RED_TARGETS_TXT}")

        try:
            req_data = json.dumps({"targets": ips}).encode("utf-8")
            req = urllib.request.Request(
                AWD_RED_API_TARGETS,
                data=req_data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                if resp.status == 200:
                    print(f"[+] 已向 AWD-Red 平台实时激活 {len(ips)} 个目标靶机")
        except Exception:
            pass
    except Exception as e:
        pass


async def check_target_alive(ip, port, timeout=2.0):
    """轻量并发 TCP 探测，快速判断靶机端口是否存活"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, int(port)),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def probe_round(db_path=DB_PATH):
    """一轮全量并发探活并仅记录存活时间"""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id, ip, port, target_url, last_seen FROM targets;")
    targets = cur.fetchall()
    conn.close()

    if not targets:
        return 0, 0

    # 并发探活
    tasks = [check_target_alive(t["ip"], t["port"]) for t in targets]
    results = await asyncio.gather(*tasks)

    # 存活则刷新纯时间 (HH:MM:SS)，失联则保持不动
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    now_time_only = time.strftime("%H:%M:%S")

    alive_count = 0
    dead_count = 0

    for t, is_alive in zip(targets, results):
        if is_alive:
            alive_count += 1
            cur.execute("UPDATE targets SET last_seen=? WHERE id=?;", (now_time_only, t["id"]))
        else:
            dead_count += 1

    conn.commit()
    conn.close()
    return alive_count, dead_count


async def probe_single_vuln(target_info, vuln, timeout=2.0):
    """异步轻量无害验证单个靶机上的后门/缺陷存活性 (支持对手与我方机器)"""
    import urllib.parse
    import random

    target_ip = target_info["ip"]
    target_role = target_info["role"]
    target_base = target_info["target_url"].rstrip("/")

    rel_file = vuln["file"].lstrip("/")
    candidates = [rel_file]
    for prefix in ["html/", "www/", "public/"]:
        if rel_file.startswith(prefix):
            candidates.append(rel_file[len(prefix):])

    params = vuln.get("param", "")
    method = "POST"
    param_name = "cmd"
    if params:
        p_first = params.split(",")[0].strip()
        if ":" in p_first:
            m, p = p_first.split(":", 1)
            method = m.strip().upper() if m.strip().upper() in ["GET", "POST"] else "POST"
            param_name = p.strip()

    kind = vuln.get("vuln_type", "suspicious")
    nonce = random.randint(100000, 999999)
    token_str = f"AWD_OK_{nonce}"
    payload = f"echo {token_str}" if kind == "cmd" else f"print('{token_str}');"

    loop = asyncio.get_running_loop()

    def _sync_request():
        import urllib.request
        for cand in candidates:
            test_url = f"{target_base}/{cand}"
            try:
                if method == "POST":
                    data = urllib.parse.urlencode({param_name: payload}).encode("utf-8")
                    req = urllib.request.Request(test_url, data=data, headers={"User-Agent": "AWD-VulnProbe/1.0"})
                else:
                    delim = "&" if "?" in test_url else "?"
                    full_url = f"{test_url}{delim}{urllib.parse.urlencode({param_name: payload})}"
                    req = urllib.request.Request(full_url, headers={"User-Agent": "AWD-VulnProbe/1.0"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    body = resp.read().decode("utf-8", errors="ignore")
                    if token_str in body:
                        return True
            except Exception:
                continue
        return False

    try:
        is_alive = await loop.run_in_executor(None, _sync_request)
        return vuln["id"], target_ip, target_role, is_alive
    except Exception:
        return vuln["id"], target_ip, target_role, False


async def probe_vulns_round(db_path=DB_PATH):
    """一轮全量并发对所有对手存活靶机 + 我方靶机执行按题型精准路由的无害存活探活"""
    conn = get_db_connection(db_path)
    cur = conn.cursor()

    # 1. 查询所有靶机 (对手仅选择端口已存活的机器，我方靶机常态探活自查)
    cur.execute("SELECT id, app, ip, port, role, target_url, last_seen FROM targets;")
    target_rows = [dict(r) for r in cur.fetchall()]

    cur.execute("SELECT id, app, file, line, vuln_type, param FROM vulns;")
    vulns = [dict(r) for r in cur.fetchall()]
    conn.close()

    if not vulns or not target_rows:
        return 0, 0, 0

    # 2. 对每个漏洞，精准查找该题型下所有【端口存活的对手】以及【我方防守机】
    tasks = []
    for v in vulns:
        matching_targets = [
            t for t in target_rows
            if t["app"] == v["app"] and t.get("target_url") and (t["role"] == "self" or t.get("last_seen") is not None)
        ]
        for t in matching_targets:
            tasks.append(probe_single_vuln(t, v))

    if not tasks:
        return 0, 0, len(vulns)

    results = await asyncio.gather(*tasks)

    # 3. 统计各漏洞暗桩在各靶机上的连通情况
    vuln_hits = {v["id"]: {"self": [], "opponents": []} for v in vulns}
    for vid, ip, role, is_alive in results:
        if is_alive:
            if role == "self":
                vuln_hits[vid]["self"].append(ip)
            else:
                vuln_hits[vid]["opponents"].append(ip)

    conn = get_db_connection(db_path)
    cur = conn.cursor()
    verified_alive = 0
    opponents_alive = 0

    for vid, hits in vuln_hits.items():
        self_list = sorted(list(set(hits["self"])))
        opp_list = sorted(list(set(hits["opponents"])))
        any_alive = 1 if (self_list or opp_list) else 0
        if any_alive:
            verified_alive += 1
        if opp_list:
            opponents_alive += 1

        parts = []
        if self_list:
            parts.append("self:" + ",".join(self_list))
        if opp_list:
            parts.append("opponents:" + ",".join(opp_list))
        live_str = "|".join(parts)

        cur.execute("UPDATE vulns SET verified = ?, live_targets = ? WHERE id = ?;", (any_alive, live_str, vid))

    conn.commit()
    conn.close()
    return verified_alive, opponents_alive, len(vulns)


async def probe_single_shell(shell, targets=None, timeout=2.0):
    """检测单个 Web 脚本端点/WebShell 是否存活 (< 400 视为存活)"""
    urls_to_test = []
    sample = (shell.get("sample_payload") or "").strip()
    if sample.startswith("http://") or sample.startswith("https://"):
        urls_to_test.append(sample)

    file_path = (shell.get("file") or "").strip().lstrip("/")
    if targets and file_path:
        for t in targets:
            if t.get("app") == shell.get("app") and t.get("target_url"):
                if t.get("role") == "opponent" and t.get("last_seen") is None:
                    continue
                url = f"{t['target_url'].rstrip('/')}/{file_path}"
                if url not in urls_to_test:
                    urls_to_test.append(url)

    if not urls_to_test and file_path:
        urls_to_test.append(f"http://127.0.0.1/{file_path}")

    loop = asyncio.get_running_loop()

    def _sync_check():
        import urllib.request
        for test_url in urls_to_test:
            try:
                req = urllib.request.Request(test_url, headers={"User-Agent": "AWD-ShellProbe/1.0"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if resp.status < 400:
                        return True, test_url
            except urllib.error.HTTPError as he:
                if he.code < 400 or he.code == 403:
                    return True, test_url
            except Exception:
                continue
        return False, (urls_to_test[0] if urls_to_test else "")

    try:
        is_alive, live_url = await loop.run_in_executor(None, _sync_check)
        return shell["id"], is_alive, live_url
    except Exception:
        return shell["id"], False, ""


async def probe_shells_round(db_path=DB_PATH):
    """一轮全量并发对所有 shell 表中记录进行轻量 HTTP 存活探活"""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id, app, file, password, method, shell_type, sample_payload FROM shell;")
    shells = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT id, app, ip, port, role, target_url, last_seen FROM targets;")
    targets = [dict(r) for r in cur.fetchall()]
    conn.close()

    if not shells:
        return 0, 0

    tasks = [probe_single_shell(s, targets) for s in shells]
    results = await asyncio.gather(*tasks)

    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    alive_count = 0
    for sid, is_alive, live_url in results:
        status_int = 1 if is_alive else 0
        if is_alive:
            alive_count += 1
        cur.execute("UPDATE shell SET is_alive = ?, last_check = ? WHERE id = ?;", (status_int, now_str, sid))
    conn.commit()
    conn.close()
    return alive_count, len(shells)


async def daemon_loop(interval=5, db_path=DB_PATH):
    """常驻后台的看门狗循环：默认每 5 秒探测一次靶机，每 15 秒探活漏洞暗桩与脚本端点"""
    print(f"[*] AWD 资产看门狗守护循环已激活 (探活间隔: {interval}s, 数据库: {db_path})")
    round_count = 0
    while True:
        try:
            t0 = time.perf_counter()
            alive, dead = await probe_round(db_path)
            cost = time.perf_counter() - t0
            now_str = time.strftime("%H:%M:%S")
            print(f"[{now_str}] 靶机探活: {alive} 存活 | {dead} 离线 (耗时: {cost:.2f}s)")

            round_count += 1
            if round_count % 3 == 1:
                v_alive, v_opp, v_total = await probe_vulns_round(db_path)
                if v_total > 0:
                    print(f"[{now_str}] 漏洞探活: {v_alive}/{v_total} 存活有效 (🎯 沦陷对手: {v_opp})")
                s_alive, s_total = await probe_shells_round(db_path)
                if s_total > 0:
                    print(f"[{now_str}] 脚本端点探活: {s_alive}/{s_total} 存活")
        except Exception as e:
            print(f"[!] 探活异常: {e}")
        await asyncio.sleep(interval)


def run_daemon_process(interval=5, db_path=DB_PATH):
    """守护进程入口"""
    # 写入 PID 文件
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

    def sig_handler(signum, frame):
        if PID_FILE.exists():
            PID_FILE.unlink(missing_ok=True)
        sys.exit(0)

    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)

    try:
        asyncio.run(daemon_loop(interval, db_path))
    finally:
        if PID_FILE.exists():
            PID_FILE.unlink(missing_ok=True)


def start_daemon_background(interval=5):
    """启动后台守护进程 (守护进程自拉起)"""
    if PID_FILE.exists():
        try:
            with open(PID_FILE, "r") as f:
                old_pid = int(f.read().strip())
            os.kill(old_pid, 0)
            print(f"[!] 守护进程已在运行中 (PID: {old_pid})")
            return old_pid
        except (OSError, ValueError):
            PID_FILE.unlink(missing_ok=True)

    script_path = Path(__file__).resolve()
    python_bin = sys.executable

    # 使用 nohup 后台静默启动
    cmd = f'nohup "{python_bin}" -u "{script_path}" run-daemon --interval {interval} >> "{LOG_FILE}" 2>&1 &'
    os.system(cmd)
    time.sleep(1)

    if PID_FILE.exists():
        with open(PID_FILE, "r") as f:
            pid = f.read().strip()
        print(f"[✅] 探活看门狗已在后台启动 (PID: {pid}, 轮询间隔: {interval}s)")
        print(f"[*] 监控日志: {LOG_FILE}")
        return int(pid)
    else:
        print("[-] 后台启动失败，请检查日志: " + str(LOG_FILE))
        return None


def stop_daemon():
    """安全停止后台守护进程"""
    if not PID_FILE.exists():
        print("[!] 当前没有运行中的看门狗守护进程。")
        return

    try:
        with open(PID_FILE, "r") as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGTERM)
        time.sleep(0.5)
        print(f"[✅] 看门狗守护进程已安全停止 (PID: {pid})")
    except ProcessLookupError:
        print("[!] 进程不存在，清理残留 PID 文件。")
    except Exception as e:
        print(f"[-] 停止失败: {e}")
    finally:
        PID_FILE.unlink(missing_ok=True)


def show_status(db_path=DB_PATH):
    """打印当前数据库状态与存活看板 (仅展示存活时间)"""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id, app, ip, port, role, target_url, last_seen FROM targets ORDER BY app, role, id;")
    rows = cur.fetchall()
    conn.close()

    daemon_status = "未运行"
    if PID_FILE.exists():
        try:
            with open(PID_FILE, "r") as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            daemon_status = f"运行中 (PID: {pid})"
        except Exception:
            daemon_status = "异常/残留"

    print("\n" + "=" * 68)
    print(f"AWD 资产态势 (awd.db) | 探活看门狗: {daemon_status}")
    print("=" * 68)
    print(f"{'ID':<4} | {'题型':<10} | {'角色':<9} | {'目标 URL':<26} | {'存活时间 (Last Seen)'}")
    print("-" * 68)
    for r in rows:
        seen = r["last_seen"] or "-"
        print(f"{r['id']:<4} | {r['app']:<10} | {r['role']:<9} | {r['target_url']:<26} | {seen}")
    print("=" * 68 + "\n")


def get_live_urls(app=None, role="opponent", threshold_seconds=15, db_path=DB_PATH):
    """根据最新存活纯时间提取在线目标 URL"""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    query = "SELECT target_url, last_seen FROM targets WHERE role=? AND last_seen IS NOT NULL"
    params = [role]
    if app:
        query += " AND app=?"
        params.append(app)
    query += " ORDER BY id;"

    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()

    today_str = time.strftime("%Y-%m-%d")
    now = time.time()
    urls = []
    for r in rows:
        try:
            seen_val = r["last_seen"]
            # 兼容纯时间 %H:%M:%S 与旧的完整时间
            if len(seen_val) == 8:
                full_ts = f"{today_str} {seen_val}"
            else:
                full_ts = seen_val
            seen_epoch = time.mktime(time.strptime(full_ts, "%Y-%m-%d %H:%M:%S"))
            if (now - seen_epoch) <= threshold_seconds:
                urls.append(r["target_url"])
        except Exception:
            continue
    return urls


def cmd_add(ip, port=80, role="opponent", app="web", ssh_port=22, ssh_user="ctf", ssh_pass=None, ssh_key=None, db_path=DB_PATH):
    """录入单个资产 (支持标记我方防守机并存入 SSH 凭据)"""
    init_database(db_path)
    clean_ip, clean_port = parse_ip_port(ip, default_port=port)
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    target_url = f"http://{clean_ip}/" if clean_port == 80 else f"http://{clean_ip}:{clean_port}/"
    cur.execute("""
        INSERT INTO targets (app, ip, port, role, target_url, ssh_port, ssh_user, ssh_pass, ssh_key, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'unknown')
        ON CONFLICT(app, ip, port) DO UPDATE SET
            role=excluded.role,
            target_url=excluded.target_url,
            ssh_port=excluded.ssh_port,
            ssh_user=excluded.ssh_user,
            ssh_pass=coalesce(excluded.ssh_pass, targets.ssh_pass),
            ssh_key=coalesce(excluded.ssh_key, targets.ssh_key);
    """, (app, clean_ip, clean_port, role, target_url, int(ssh_port), ssh_user, ssh_pass, ssh_key))
    conn.commit()
    conn.close()
    role_icon = "🛡️ 我方防守靶机" if role == "self" else "🎯 对手靶机"
    print(f"\n[+] 成功录入资产 [{role_icon}]: {clean_ip}")
    print(f"    - Web: {target_url}")
    print(f"    - SSH: {ssh_user}@{clean_ip}:{ssh_port}")
    if ssh_pass:
        print(f"    - 凭据: 密码已安全存入")
    print(f"    - 题型: {app}\n")

    if role == "self":
        try:
            import importlib
            ssh_utils = None
            for p in [AWD_RED_DIR / "server", AWD_RED_DIR / "tools"]:
                if (p / "ssh_utils.py").exists():
                    sys.path.insert(0, str(p))
                    ssh_utils = importlib.import_module("ssh_utils")
                    break
            if ssh_utils and hasattr(ssh_utils, "setup_self_ssh_key"):
                print(f"[*] 正在为我方自机 {clean_ip} 配置 SSH 免密...")
                ok, msg, key_p = ssh_utils.setup_self_ssh_key(clean_ip, port=int(ssh_port), user=ssh_user, password=ssh_pass)
                if ok:
                    print(f"[+] ✅ {msg} ({key_p})\n")
                else:
                    print(f"[-] ⚠️ {msg}\n")
        except Exception as e:
            pass


def cmd_add_server(url, name="flag_server", db_path=DB_PATH):
    """录入或更新裁判平台/Flag提交服务器资产 (role='server')"""
    init_database(db_path)
    url = (url or "").strip()
    if not url:
        print("[-] 请提供有效的裁判平台 URL")
        return

    parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    full_url = url if "://" in url else f"http://{url}"

    conn = get_db_connection(db_path)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO targets (app, ip, port, role, target_url, status)
        VALUES (?, ?, ?, 'server', ?, 'unknown')
        ON CONFLICT(app, ip, port) DO UPDATE SET
            role='server',
            target_url=excluded.target_url;
    """, (name, host, port, full_url))

    # 同时联动写入 config 表的 flag_server，确保老旧脚本完全兼容
    cur.execute("INSERT OR REPLACE INTO config (key, value, updated_at) VALUES ('flag_server', ?, CURRENT_TIMESTAMP);", (full_url,))

    conn.commit()
    conn.close()
    print(f"\n[+] 成功登记裁判平台/提交服务器资产 [🌐 裁判平台]:")
    print(f"    - IP/主机: {host}:{port}")
    print(f"    - 提交接口: {full_url}")
    print(f"    - 资产角色: server (已加入自动探活与大盘态势)\n")


def cmd_config(key=None, value=None, db_path=DB_PATH):
    """查看或设置比赛配置 (flag_server, token 等)"""
    init_database(db_path)
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    if key and value is not None:
        cur.execute("INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP);", (key.strip(), value.strip()))
        conn.commit()
        conn.close()
        print(f"[+] 比赛配置已更新: {key.strip()} = {value.strip()}")
        if key.strip() == "flag_server":
            cmd_add_server(value.strip(), db_path=db_path)
        return
    elif key:
        cur.execute("SELECT value FROM config WHERE key = ?;", (key.strip(),))
        row = cur.fetchone()
        if row:
            print(row[0])
        else:
            print(f"[-] 未配置 {key.strip()}")
    else:
        cur.execute("SELECT key, value, updated_at FROM config ORDER BY key;")
        rows = [dict(r) for r in cur.fetchall()]
        print("\n=== AWD 比赛配置 (config) ===")
        if not rows:
            print("暂无全局配置 (可通过 config flag_server <url> 写入)")
        for r in rows:
            print(f"  {r['key']:<15} = {r['value']}")
        print()
    conn.close()


def cmd_clean(target_table="all", db_path=DB_PATH):
    """清理指定数据表并彻底重置自增 ID 计数器 (归零至 1)"""
    init_database(db_path)
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    target_lower = (target_table or "all").lower().strip()

    valid_tables = ["vulns", "flags", "targets", "backdoors", "shell"]
    if target_lower in ["all", "*"]:
        to_clean = valid_tables
    elif target_lower in ["shell", "shells"]:
        to_clean = ["shell"]
    elif target_lower in ["backdoor", "backdoors"]:
        to_clean = ["backdoors"]
    elif target_lower in valid_tables:
        to_clean = [target_lower]
    else:
        print(f"[-] 未知清理目标: {target_table}，支持: {', '.join(valid_tables)} 或 all")
        conn.close()
        return

    for tbl in to_clean:
        cur.execute(f"DELETE FROM {tbl};")
        cur.execute("DELETE FROM sqlite_sequence WHERE name = ?;", (tbl,))
        print(f"[+] 数据表 [{tbl}] 已彻底清空，自增 ID 已重置归零。")

    conn.commit()
    conn.close()


def cmd_query(target_type="apps", filter_sub=None, show_all=False, urls_only=False, ips_only=False, as_json=False, db_path=DB_PATH):
    """直接按一种类型查询资产/漏洞/Flag/题型概览，杜绝手写 SQL"""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    target_type_lower = (target_type or "apps").lower().strip()

    # 1. 查询题型概览 (apps / types / overview)
    if target_type_lower in ["apps", "types", "overview"]:
        cur.execute("SELECT app, COUNT(*) as total, SUM(CASE WHEN last_seen IS NOT NULL THEN 1 ELSE 0 END) as alive FROM targets GROUP BY app;")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        if as_json:
            print(json.dumps(rows, indent=2, ensure_ascii=False))
        else:
            print(f"\n{'App (题型)':<16} | {'总靶机数':<10} | {'当前存活数'}")
            print("-" * 42)
            for r in rows:
                print(f"{r['app']:<16} | {r['total']:<10} | {r['alive']}")
            print()
        return

    # 2. 查询我方防守靶机 (self)
    if target_type_lower == "self":
        cur.execute("SELECT id, app, ip, port, target_url, ssh_port, ssh_user, ssh_pass, last_seen FROM targets WHERE role='self' ORDER BY id;")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        if urls_only:
            for r in rows: print(r["target_url"])
        elif ips_only:
            for r in rows: print(r["ip"])
        elif as_json:
            print(json.dumps(rows, indent=2, ensure_ascii=False))
        else:
            print(f"\n{'ID':<4} | {'题型':<8} | {'我方 Web URL':<26} | {'SSH 登录凭据':<30} | {'最近心跳'}")
            print("-" * 80)
            for r in rows:
                ssh_info = f"{r.get('ssh_user') or 'ctf'}:{r.get('ssh_pass') or '***'}@{r['ip']}:{r.get('ssh_port') or 22}"
                print(f"{r['id']:<4} | {r['app']:<8} | {r['target_url']:<26} | {ssh_info:<30} | {r['last_seen'] or '离线'}")
            print()
        return

    # 3. 查询挖掘到的漏洞 (vulns [app])
    if target_type_lower == "vulns":
        query = "SELECT id, app, file, line, vuln_type, param, poc_template, coalesce(verified, 0) as verified, coalesce(live_targets, '') as live_targets FROM vulns"
        params = []
        if filter_sub:
            query += " WHERE app = ?"
            params.append(filter_sub)
        query += " ORDER BY id;"
        cur.execute(query, params)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        if as_json:
            print(json.dumps(rows, indent=2, ensure_ascii=False))
        else:
            print(f"\n{'ID':<4} | {'题型':<10} | {'文件路径':<28} | {'类型':<7} | {'入参':<12} | {'探活命中目标 (对手 / 我方)'}")
            print("-" * 95)
            for r in rows:
                lt = r.get("live_targets", "")
                parts = []
                if "opponents:" in lt:
                    opp = lt.split("opponents:")[1].split("|")[0]
                    parts.append(f"🎯 沦陷对手:[{opp}]")
                if "self:" in lt:
                    sf = lt.split("self:")[1].split("|")[0]
                    parts.append(f"🛡️ 我方存活:[{sf}]")
                status_txt = " ".join(parts) if parts else "⚪ 待突破"
                file_line = f"{r['file'][:24]}:{r['line']}" if r.get("line") else r["file"][:28]
                print(f"{r['id']:<4} | {r['app']:<10} | {file_line:<28} | {r['vuln_type']:<7} | {(r['param'] or '-')[:12]:<12} | {status_txt}")
            print()
        return

    # 4. 查询 Flag 战果 (flags)
    if target_type_lower == "flags":
        cur.execute("SELECT id, round, app, target_ip, flag, submit_status, created_at FROM flags ORDER BY id DESC;")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        if as_json:
            print(json.dumps(rows, indent=2, ensure_ascii=False))
        else:
            print(f"\n{'ID':<4} | {'轮次':<5} | {'题型':<10} | {'目标 IP':<16} | {'Flag':<32} | {'状态'}")
            print("-" * 78)
            for r in rows:
                print(f"{r['id']:<4} | {r['round']:<5} | {r['app']:<10} | {r['target_ip']:<16} | {r['flag']:<32} | {r['submit_status']}")
            print()
        return

    # 5. 查询 Web 脚本与端点资产 (shell / shells)
    if target_type_lower in ["shell", "shells"]:
        cur.execute("SELECT id, app, file, password, method, shell_type, sample_payload, flag_cmd, coalesce(is_alive, 0) as is_alive, last_check, created_at FROM shell ORDER BY id;")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        if as_json:
            print(json.dumps(rows, indent=2, ensure_ascii=False))
        else:
            print(f"\n{'ID':<4} | {'题型':<10} | {'文件路径':<26} | {'密码/参数':<10} | {'类型':<6} | {'存活状态':<10} | {'访问 URL / Payload'}")
            print("-" * 90)
            for r in rows:
                status_txt = "🟢 存活" if r.get("is_alive") == 1 else "🔴 离线"
                url_disp = r.get("sample_payload") or r.get("file")
                print(f"{r['id']:<4} | {r['app']:<10} | {r['file'][:24]:<26} | {(r.get('password') or '-')[:8]:<10} | {r.get('shell_type') or 'eval':<6} | {status_txt:<10} | {url_disp}")
            print()
        return

    # 6. 查询裁判平台/服务器资产 (server / servers / platform)
    if target_type_lower in ["server", "servers", "platform"]:
        cur.execute("SELECT id, app, ip, port, role, target_url, last_seen, created_at FROM targets WHERE role = 'server' ORDER BY id;")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        if as_json:
            print(json.dumps(rows, indent=2, ensure_ascii=False))
        else:
            print(f"\n{'ID':<4} | {'资产名称':<12} | {'服务器 IP:端口':<22} | {'连通状态':<10} | {'提交接口 URL'}")
            print("-" * 85)
            for r in rows:
                status_txt = "🟢 在线" if r.get("last_seen") else "🔴 未连通"
                host_port = f"{r['ip']}:{r['port']}"
                print(f"{r['id']:<4} | {r['app']:<12} | {host_port:<22} | {status_txt:<10} | {r['target_url']}")
            print()
        return

    # 7. 直接按具体题型 (如 seacms) 或 all 查询靶机
    app_filter = None if target_type_lower in ["all", "*"] else target_type

    query = "SELECT id, app, ip, port, role, target_url, last_seen FROM targets WHERE 1=1"
    params = []
    if app_filter:
        query += " AND app = ?"
        params.append(app_filter)

    if not show_all:
        # 默认：仅查询存活的对手靶机！
        query += " AND role = 'opponent' AND last_seen IS NOT NULL"

    query += " ORDER BY id;"
    cur.execute(query, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    # 存活时效门禁过滤 (20秒内有心跳算存活)
    if not show_all:
        now = time.time()
        today_str = time.strftime("%Y-%m-%d")
        alive_rows = []
        for r in rows:
            seen_val = r["last_seen"]
            if not seen_val:
                continue
            try:
                full_ts = f"{today_str} {seen_val}" if len(seen_val) == 8 else seen_val
                seen_epoch = time.mktime(time.strptime(full_ts, "%Y-%m-%d %H:%M:%S"))
                if (now - seen_epoch) <= 20:
                    alive_rows.append(r)
            except Exception:
                continue
        rows = alive_rows

    if urls_only:
        for r in rows: print(r["target_url"])
    elif ips_only:
        for r in rows: print(r["ip"])
    elif as_json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
    else:
        title = f"应用 [{app_filter}] 存活对手" if (app_filter and not show_all) else f"资产列表 ({app_filter or '全部'})"
        print(f"\n{title} (共 {len(rows)} 个):")
        print(f"{'ID':<4} | {'题型':<10} | {'角色':<9} | {'目标 URL':<28} | {'最近存活'}")
        print("-" * 65)
        for r in rows:
            print(f"{r['id']:<4} | {r['app']:<10} | {r['role']:<9} | {r['target_url']:<28} | {r['last_seen'] or '离线'}")
        print()


HTML_PAGE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AWD 攻防全景指挥大盘</title>
<style>
  :root {
    --bg-main: #0b0f19;
    --bg-card: #151d2f;
    --border: #243049;
    --text-primary: #f8fafc;
    --text-muted: #94a3b8;
    --green: #10b981;
    --red: #ef4444;
    --blue: #3b82f6;
    --yellow: #f59e0b;
    --purple: #8b5cf6;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg-main);
    color: var(--text-primary);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    padding: 24px;
    line-height: 1.5;
  }
  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 24px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border);
  }
  .title-group { display: flex; align-items: center; gap: 12px; }
  .title { font-size: 22px; font-weight: 700; color: #fff; letter-spacing: -0.5px; }
  .badge-live {
    background: rgba(16, 185, 129, 0.15);
    color: var(--green);
    border: 1px solid rgba(16, 185, 129, 0.3);
    padding: 3px 10px;
    border-radius: 9999px;
    font-size: 12px;
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .dot {
    width: 8px; height: 8px; border-radius: 50%; background: var(--green);
    box-shadow: 0 0 8px var(--green);
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.4; transform: scale(0.85); }
  }
  .controls { display: flex; align-items: center; gap: 12px; }
  .btn {
    background: #1e293b;
    color: #f1f5f9;
    border: 1px solid var(--border);
    padding: 6px 14px;
    border-radius: 6px;
    font-size: 13px;
    cursor: pointer;
    transition: all 0.2s;
  }
  .btn:hover { background: #334155; }
  .kpi-bar {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 10px 16px;
    margin-bottom: 20px;
    align-items: center;
    font-size: 13px;
  }
  .kpi-chip {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 5px 12px;
    background: rgba(15, 23, 42, 0.6);
    border-radius: 6px;
    border: 1px solid rgba(255, 255, 255, 0.05);
  }
  .kpi-chip b { font-weight: 600; color: #fff; }
  
  .panel {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 20px;
    overflow: hidden;
  }
  .panel-header {
    background: rgba(30, 41, 59, 0.5);
    padding: 10px 18px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border);
  }
  .panel-title { font-size: 14px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
  .table-responsive { width: 100%; overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th {
    background: rgba(15, 23, 42, 0.7);
    color: var(--text-muted);
    font-weight: 600;
    text-align: left;
    padding: 8px 14px;
    border-bottom: 1px solid var(--border);
    font-size: 12px;
  }
  td {
    padding: 8px 14px;
    border-bottom: 1px solid rgba(36, 48, 73, 0.6);
  }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(30, 41, 59, 0.4); }
  
  .tag {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 500;
  }
  .tag-alive { background: rgba(16, 185, 129, 0.15); color: var(--green); }
  .tag-dead { background: rgba(239, 68, 68, 0.15); color: var(--red); }
  .tag-self { background: rgba(59, 130, 246, 0.15); color: var(--blue); }
  .tag-opponent { background: rgba(245, 158, 11, 0.15); color: var(--yellow); }
  .tag-vuln { background: rgba(139, 92, 246, 0.15); color: var(--purple); }
  
  a.url-link { color: #38bdf8; text-decoration: none; font-family: ui-monospace, monospace; }
  a.url-link:hover { text-decoration: underline; }
  .mono { font-family: ui-monospace, monospace; }
  .search-input {
    background: #0f172a;
    border: 1px solid var(--border);
    color: #fff;
    padding: 5px 12px;
    border-radius: 4px;
    font-size: 12px;
  }
</style>
</head>
<body>
  <div class="header">
    <div class="title-group">
      <div class="title">⚡ AWD 攻防全景指挥大盘</div>
      <div class="badge-live"><div class="dot"></div>实时同步 (127.0.0.1:8090)</div>
    </div>
    <div class="controls">
      <span id="last-sync" style="font-size: 12px; color: var(--text-muted);">正在同步...</span>
      <button class="btn" onclick="fetchStatus()">🔄 手动刷新</button>
    </div>
  </div>

  <div class="kpi-bar">
    <div class="kpi-chip">🎯 靶机在线: <b id="kpi-alive">-</b> (<span id="kpi-rate">-</span>)</div>
    <div class="kpi-chip">⚡ 存活暗桩: <b id="kpi-vulns-verified" style="color:var(--green);">-</b> / <span id="kpi-vulns">-</span></div>
    <div class="kpi-chip">🐚 脚本端点: <b id="kpi-shells-alive" style="color:var(--green);">-</b> / <span id="kpi-shells">-</span> 在线</div>
    <div class="kpi-chip">🏁 Flag 入账: <b id="kpi-flags-success" style="color:var(--yellow);">-</b> (<span id="kpi-flags">-</span> 捕获)</div>
    <div class="kpi-chip">⏱️ 看门狗: <b id="kpi-daemon" style="color:var(--green);">运行中</b></div>
    <div class="kpi-chip" style="flex: 1; min-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
      🌐 平台: <span class="mono" id="kpi-flag-server" style="color:#38bdf8;">未配置</span>
    </div>
  </div>

  <!-- Panel 1: Targets -->
  <div class="panel">
    <div class="panel-header">
      <div class="panel-title">🎯 目标靶机态势 (Targets)</div>
      <div style="display:flex; gap: 8px;">
        <button class="btn" onclick="filterTargets('alive')">🟢 存活对手</button>
        <button class="btn" onclick="filterTargets('all')">全部</button>
        <button class="btn" onclick="filterTargets('self')">🛡️ 我方</button>
        <button class="btn" onclick="filterTargets('server')">🌐 平台</button>
        <input class="search-input" id="search-target" placeholder="搜索 IP / 题型..." onkeyup="renderTargets()">
      </div>
    </div>
    <div class="table-responsive">
      <table>
        <thead>
          <tr>
            <th style="width: 50px;">ID</th>
            <th>题型 (App)</th>
            <th>角色与状态</th>
            <th>目标 IP / Web (点击跳转)</th>
            <th>最新心跳</th>
          </tr>
        </thead>
        <tbody id="tbody-targets">
          <tr><td colspan="5" style="text-align:center; color: var(--text-muted);">数据加载中...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Panel 2: Vulns -->
  <div class="panel">
    <div class="panel-header">
      <div class="panel-title">🔍 代码缺陷与后门清单 (Vulns)</div>
      <div style="display:flex; gap: 8px; align-items: center;">
        <button class="btn" id="btn-verify-vulns" onclick="triggerVulnVerify()">⚡ 立即验证存活</button>
        <input class="search-input" id="search-vuln" placeholder="过滤缺陷 / 文件..." onkeyup="renderVulns()">
      </div>
    </div>
    <div class="table-responsive">
      <table>
        <thead>
          <tr>
            <th style="width: 50px;">ID</th>
            <th>题型</th>
            <th>缺陷文件路径</th>
            <th>分类</th>
            <th>触发入参</th>
            <th>存活探活</th>
          </tr>
        </thead>
        <tbody id="tbody-vulns">
          <tr><td colspan="6" style="text-align:center; color: var(--text-muted);">暂无发现漏洞</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Panel 3: Shells -->
  <div class="panel">
    <div class="panel-header">
      <div class="panel-title">🐚 脚本与端点资产清单 (Shell)</div>
      <div style="display:flex; gap: 8px; align-items: center;">
        <button class="btn" id="btn-verify-shells" onclick="triggerShellVerify()">⚡ 验证端点存活</button>
        <input class="search-input" id="search-shell" placeholder="过滤脚本 / 文件..." onkeyup="renderShells()">
      </div>
    </div>
    <div class="table-responsive">
      <table>
        <thead>
          <tr>
            <th style="width: 50px;">ID</th>
            <th>题型</th>
            <th>文件路径</th>
            <th>访问 URL / Payload (点击跳转)</th>
            <th>密码/参数</th>
            <th>类型</th>
            <th>存活状态</th>
            <th>最近检测</th>
          </tr>
        </thead>
        <tbody id="tbody-shells">
          <tr><td colspan="8" style="text-align:center; color: var(--text-muted);">暂无登记脚本</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Panel 4: Flags -->
  <div class="panel">
    <div class="panel-header">
      <div class="panel-title">🏁 Flag 战果榜与提交审计 (Flags)</div>
    </div>
    <div class="table-responsive">
      <table>
        <thead>
          <tr>
            <th style="width: 50px;">ID</th>
            <th>轮次</th>
            <th>题型</th>
            <th>目标靶机 IP</th>
            <th>Flag 凭据</th>
            <th>提交判定</th>
            <th>记录时间</th>
          </tr>
        </thead>
        <tbody id="tbody-flags">
          <tr><td colspan="7" style="text-align:center; color: var(--text-muted);">暂无 Flag 记录</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <script>
    let globalData = { targets: [], vulns: [], flags: [], stats: {} };
    let currentTargetFilter = 'alive';

    function fetchStatus() {
      fetch('/api/status')
        .then(r => r.json())
        .then(data => {
          globalData = data;
          document.getElementById('last-sync').innerText = '最后同步: ' + new Date().toLocaleTimeString();
          renderStats(data.stats);
          let serverTarget = (data.targets || []).find(t => t.role === 'server');
          if (serverTarget) {
            let statusBadge = serverTarget.is_alive ? ' <span style="color:var(--green); font-size:11px;">(🟢 在线)</span>' : ' <span style="color:var(--red); font-size:11px;">(🔴 离线)</span>';
            document.getElementById('kpi-flag-server').innerHTML = `<a href="${serverTarget.target_url}" target="_blank" style="color:#38bdf8; text-decoration:none;">${serverTarget.target_url}</a>${statusBadge}`;
          } else if (data.config && data.config.flag_server) {
            document.getElementById('kpi-flag-server').innerText = data.config.flag_server;
          } else {
            document.getElementById('kpi-flag-server').innerText = '未配置';
          }
          renderTargets();
          renderVulns();
          renderShells();
          renderFlags();
        })
        .catch(err => {
          document.getElementById('last-sync').innerText = '连接中断: ' + err;
        });
    }

    function renderStats(stats) {
      if (!stats) return;
      document.getElementById('kpi-alive').innerText = stats.alive_targets + ' / ' + stats.total_targets;
      let rate = stats.total_targets > 0 ? Math.round((stats.alive_targets / stats.total_targets) * 100) : 0;
      document.getElementById('kpi-rate').innerText = '在线率 ' + rate + '%';
      document.getElementById('kpi-vulns').innerText = stats.vulns_count || 0;
      let oppCount = stats.vulns_opponents || 0;
      let totalAlive = stats.vulns_verified || 0;
      document.getElementById('kpi-vulns-verified').innerText = `${oppCount} 对手沦陷 (${totalAlive} 存活)`;
      document.getElementById('kpi-shells').innerText = stats.shells_count || 0;
      document.getElementById('kpi-shells-alive').innerText = stats.shells_alive || 0;
      document.getElementById('kpi-flags').innerText = stats.flags_count || 0;
      document.getElementById('kpi-flags-success').innerText = (stats.flags_success || 0) + ' 成功入账';
      document.getElementById('kpi-daemon').innerText = stats.daemon_running ? '🟢 运行中 (5s)' : '🔴 未运行';
      document.getElementById('kpi-daemon').style.color = stats.daemon_running ? 'var(--green)' : 'var(--red)';
    }

    function filterTargets(filterMode) {
      if (filterMode) currentTargetFilter = filterMode;
      renderTargets();
    }

    function renderTargets() {
      const tbody = document.getElementById('tbody-targets');
      const q = (document.getElementById('search-target').value || '').toLowerCase();
      let list = globalData.targets || [];

      if (currentTargetFilter === 'alive') {
        list = list.filter(t => t.is_alive && t.role === 'opponent');
      } else if (currentTargetFilter === 'self') {
        list = list.filter(t => t.role === 'self');
      } else if (currentTargetFilter === 'server') {
        list = list.filter(t => t.role === 'server');
      }

      if (q) {
        list = list.filter(t => (t.ip + ' ' + t.app + ' ' + t.target_url).toLowerCase().includes(q));
      }

      if (list.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 16px;">未匹配到相关靶机</td></tr>';
        return;
      }

      tbody.innerHTML = list.map(t => {
        let statusBadge = t.is_alive ? '<span class="tag tag-alive">🟢 在线</span>' : '<span class="tag tag-dead">🔴 离线</span>';
        let roleBadge = '<span class="tag tag-opponent">🎯 对手靶机</span>';
        if (t.role === 'self') {
          roleBadge = '<span class="tag tag-self">🛡️ 我方防守</span>';
        } else if (t.role === 'server') {
          roleBadge = '<span class="tag" style="background:rgba(56,189,248,0.15);color:#38bdf8;">🌐 裁判平台</span>';
        }
        return `<tr>
          <td>${t.id}</td>
          <td><span class="tag tag-vuln" style="font-weight:600;">${t.app}</span></td>
          <td>${roleBadge} ${statusBadge}</td>
          <td class="mono"><a class="url-link" href="${t.target_url}" target="_blank">${t.ip} (${t.target_url}) ↗</a></td>
          <td class="mono" style="font-size:12px; color:var(--text-muted);">${t.last_seen || '-'}</td>
        </tr>`;
      }).join('');
    }

    function renderVulns() {
      const tbody = document.getElementById('tbody-vulns');
      const q = (document.getElementById('search-vuln').value || '').toLowerCase();
      let list = globalData.vulns || [];
      if (q) {
        list = list.filter(v => (v.file + ' ' + v.app + ' ' + v.vuln_type + ' ' + (v.param||'') + ' ' + (v.live_targets||'')).toLowerCase().includes(q));
      }

      if (list.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: var(--text-muted); padding: 16px;">暂无发现漏洞</td></tr>';
        return;
      }

      tbody.innerHTML = list.map(v => {
        let liveStr = v.live_targets || '';
        let badges = [];
        if (liveStr.includes('opponents:')) {
          let oppPart = liveStr.split('opponents:')[1].split('|')[0];
          badges.push(`<span class="tag tag-opponent" style="font-weight:600;">🎯 沦陷对手: ${oppPart}</span>`);
        }
        if (liveStr.includes('self:')) {
          let selfPart = liveStr.split('self:')[1].split('|')[0];
          badges.push(`<span class="tag tag-self" style="font-size:11px;">🛡️ 我方存活: ${selfPart}</span>`);
        }
        let verifyBadge = badges.length > 0 ? badges.join(' ') : '<span class="tag" style="background:#334155;color:#94a3b8;">⚪ 待突破</span>';
        let paramStr = v.param ? `<span class="mono" style="color:var(--yellow);">${v.param}</span>` : '<span style="color:var(--text-muted);">-</span>';
        let fileLine = v.line ? `${v.file}:${v.line}` : v.file;
        return `<tr>
          <td>${v.id}</td>
          <td><span class="tag tag-vuln">${v.app}</span></td>
          <td class="mono"><b>${fileLine}</b></td>
          <td><span class="tag" style="background:rgba(255,255,255,0.08);">${v.vuln_type}</span></td>
          <td>${paramStr}</td>
          <td>${verifyBadge}</td>
        </tr>`;
      }).join('');
    }

    function renderShells() {
      const tbody = document.getElementById('tbody-shells');
      const q = (document.getElementById('search-shell').value || '').toLowerCase();
      let list = globalData.shells || [];
      if (q) {
        list = list.filter(s => (s.file + ' ' + s.app + ' ' + (s.password||'') + ' ' + (s.sample_payload||'')).toLowerCase().includes(q));
      }

      if (list.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color: var(--text-muted); padding: 16px;">暂无登记脚本</td></tr>';
        return;
      }

      tbody.innerHTML = list.map(s => {
        let isAlive = s.is_alive === 1;
        let statusBadge = isAlive ? '<span class="tag tag-alive">🟢 存活</span>' : '<span class="tag tag-dead">🔴 离线/失效</span>';
        let urlText = s.sample_payload || s.file;
        let urlLink = (urlText.startsWith('http://') || urlText.startsWith('https://'))
          ? `<a class="url-link" href="${urlText}" target="_blank">${urlText} ↗</a>`
          : `<span class="mono">${urlText}</span>`;
        let passStr = s.password ? `<span class="mono" style="color:var(--yellow);">${s.password}</span>` : '<span style="color:var(--text-muted);">-</span>';
        return `<tr>
          <td>${s.id}</td>
          <td><span class="tag tag-vuln">${s.app}</span></td>
          <td class="mono"><b>${s.file}</b></td>
          <td class="mono">${urlLink}</td>
          <td>${passStr}</td>
          <td><span class="tag" style="background:rgba(255,255,255,0.08);">${s.shell_type || 'eval'}</span></td>
          <td>${statusBadge}</td>
          <td class="mono" style="font-size:12px; color:var(--text-muted);">${s.last_check || s.created_at || '-'}</td>
        </tr>`;
      }).join('');
    }

    function renderFlags() {
      const tbody = document.getElementById('tbody-flags');
      let list = globalData.flags || [];

      if (list.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color: var(--text-muted); padding: 20px;">暂无 Flag 记录</td></tr>';
        return;
      }

      tbody.innerHTML = list.map(f => {
        let badge = '<span class="tag" style="background:#334155;">' + f.submit_status + '</span>';
        if (f.submit_status === 'success') badge = '<span class="tag tag-alive">✅ 成功</span>';
        else if (f.submit_status === 'duplicate' || f.submit_status === 'already_submitted') badge = '<span class="tag tag-opponent">🔁 重复</span>';
        else if (f.submit_status === 'failed') badge = '<span class="tag tag-dead">❌ 失败</span>';

        return `<tr>
          <td>${f.id}</td>
          <td>第 ${f.round} 轮</td>
          <td><b>${f.app}</b></td>
          <td class="mono">${f.target_ip}</td>
          <td class="mono" style="color:var(--yellow); font-weight:600;">${f.flag}</td>
          <td>${badge}</td>
          <td class="mono" style="font-size:12px; color:var(--text-muted);">${f.created_at || '-'}</td>
        </tr>`;
      }).join('');
    }

    function triggerVulnVerify() {
      const btn = document.getElementById('btn-verify-vulns');
      const origText = btn.innerText;
      btn.innerText = '⏳ 正在全量探活...';
      btn.disabled = true;
      fetch('/api/vuln/verify', { method: 'POST' })
        .then(r => r.json())
        .then(data => {
          btn.innerText = `✅ 完成 (${data.opponents || 0} 对手沦陷 / ${data.alive || 0} 存活)`;
          fetchStatus();
          setTimeout(() => { btn.innerText = origText; btn.disabled = false; }, 3000);
        })
        .catch(err => {
          btn.innerText = '❌ 探活失败';
          setTimeout(() => { btn.innerText = origText; btn.disabled = false; }, 3000);
        });
    }

    function triggerShellVerify() {
      const btn = document.getElementById('btn-verify-shells');
      const origText = btn.innerText;
      btn.innerText = '⏳ 正在探活...';
      btn.disabled = true;
      fetch('/api/shell/verify', { method: 'POST' })
        .then(r => r.json())
        .then(data => {
          btn.innerText = `✅ 完成 (${data.alive || 0}/${data.total || 0} 存活)`;
          fetchStatus();
          setTimeout(() => { btn.innerText = origText; btn.disabled = false; }, 3000);
        })
        .catch(err => {
          btn.innerText = '❌ 探活失败';
          setTimeout(() => { btn.innerText = origText; btn.disabled = false; }, 3000);
        });
    }

    fetchStatus();
    setInterval(fetchStatus, 2500);
  </script>
</body>
</html>
"""


class WebUIHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/status":
            try:
                conn = get_db_connection()
                cur = conn.cursor()

                cur.execute("SELECT id, app, ip, port, role, target_url, last_seen FROM targets ORDER BY app, role, id;")
                targets_rows = [dict(r) for r in cur.fetchall()]

                now = time.time()
                today_str = time.strftime("%Y-%m-%d")
                alive_count = 0
                for t in targets_rows:
                    seen = t.get("last_seen")
                    t["is_alive"] = False
                    if seen:
                        try:
                            full_ts = f"{today_str} {seen}" if len(seen) == 8 else seen
                            seen_epoch = time.mktime(time.strptime(full_ts, "%Y-%m-%d %H:%M:%S"))
                            if (now - seen_epoch) <= 20:
                                t["is_alive"] = True
                                alive_count += 1
                        except Exception:
                            pass

                cur.execute("SELECT id, app, file, line, vuln_type, param, poc_template, coalesce(verified, 0) as verified, coalesce(live_targets, '') as live_targets, created_at FROM vulns ORDER BY id DESC;")
                vulns_rows = [dict(r) for r in cur.fetchall()]
                vulns_verified = sum(1 for v in vulns_rows if v.get("verified") == 1)
                vulns_opponents = sum(1 for v in vulns_rows if "opponents:" in v.get("live_targets", ""))

                cur.execute("SELECT id, app, file, password, method, shell_type, sample_payload, defense_action, flag_cmd, coalesce(is_alive, 0) as is_alive, last_check, created_at FROM shell ORDER BY id DESC;")
                shells_rows = [dict(r) for r in cur.fetchall()]
                shells_alive = sum(1 for s in shells_rows if s.get("is_alive") == 1)

                cur.execute("SELECT id, round, app, target_ip, flag, submit_status, created_at FROM flags ORDER BY id DESC;")
                flags_rows = [dict(r) for r in cur.fetchall()]
                flags_success = sum(1 for f in flags_rows if f.get("submit_status") == "success")

                cur.execute("SELECT key, value FROM config;")
                config_map = {r["key"]: r["value"] for r in cur.fetchall()}

                conn.close()

                daemon_alive = False
                if PID_FILE.exists():
                    try:
                        with open(PID_FILE, "r") as f:
                            dpid = int(f.read().strip())
                        os.kill(dpid, 0)
                        daemon_alive = True
                    except Exception:
                        pass

                payload = {
                    "targets": targets_rows,
                    "vulns": vulns_rows,
                    "shells": shells_rows,
                    "flags": flags_rows,
                    "config": config_map,
                    "stats": {
                        "total_targets": len(targets_rows),
                        "alive_targets": alive_count,
                        "vulns_count": len(vulns_rows),
                        "vulns_verified": vulns_verified,
                        "vulns_opponents": vulns_opponents,
                        "shells_count": len(shells_rows),
                        "shells_alive": shells_alive,
                        "flags_count": len(flags_rows),
                        "flags_success": flags_success,
                        "daemon_running": daemon_alive,
                    }
                }
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(body)
            except Exception as e:
                err_body = json.dumps({"error": str(e)}).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(err_body)))
                self.end_headers()
                self.wfile.write(err_body)
        else:
            body = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/vuln/verify":
            try:
                v_alive, v_opp, v_total = asyncio.run(probe_vulns_round())
                body = json.dumps({"status": "ok", "alive": v_alive, "opponents": v_opp, "total": v_total}, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(body)
            except Exception as e:
                err_body = json.dumps({"error": str(e)}).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(err_body)))
                self.end_headers()
                self.wfile.write(err_body)
        elif parsed.path == "/api/shell/verify":
            try:
                s_alive, s_total = asyncio.run(probe_shells_round())
                body = json.dumps({"status": "ok", "alive": s_alive, "total": s_total}, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(body)
            except Exception as e:
                err_body = json.dumps({"error": str(e)}).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(err_body)))
                self.end_headers()
                self.wfile.write(err_body)
        else:
            self.send_response(404)
            self.end_headers()


def run_ui_process(port=UI_PORT):
    with open(UI_PID_FILE, "w") as f:
        f.write(str(os.getpid()))

    def sig_handler(signum, frame):
        if UI_PID_FILE.exists():
            UI_PID_FILE.unlink(missing_ok=True)
        sys.exit(0)

    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)

    try:
        # Strictly bind to 127.0.0.1
        server = http.server.ThreadingHTTPServer(("127.0.0.1", int(port)), WebUIHandler)
        print(f"[*] WebUI 服务器已启动: http://127.0.0.1:{port} (监听 127.0.0.1, PID: {os.getpid()})")
        server.serve_forever()
    finally:
        if UI_PID_FILE.exists():
            UI_PID_FILE.unlink(missing_ok=True)


def start_ui_background(port=UI_PORT):
    """启动后台 WebUI 服务 (严格监听 127.0.0.1)"""
    if UI_PID_FILE.exists():
        try:
            with open(UI_PID_FILE, "r") as f:
                old_pid = int(f.read().strip())
            os.kill(old_pid, 0)
            return old_pid
        except (OSError, ValueError):
            UI_PID_FILE.unlink(missing_ok=True)

    script_path = Path(__file__).resolve()
    python_bin = sys.executable
    cmd = f'nohup "{python_bin}" -u "{script_path}" run-ui --port {port} >> "{UI_LOG_FILE}" 2>&1 &'
    os.system(cmd)
    time.sleep(0.5)

    if UI_PID_FILE.exists():
        try:
            with open(UI_PID_FILE, "r") as f:
                pid = int(f.read().strip())
            print(f"[🌐] AWD 态势大盘已在后台启动: http://127.0.0.1:{port} (PID: {pid})")
            return pid
        except Exception:
            pass
    return None


def ensure_ui_running(port=UI_PORT):
    """在调用资产技能任何功能时，检测并自动拉起 WebUI"""
    if UI_PID_FILE.exists():
        try:
            with open(UI_PID_FILE, "r") as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            return pid
        except Exception:
            UI_PID_FILE.unlink(missing_ok=True)
    return start_ui_background(port=port)


def stop_ui():
    """停止 WebUI 服务"""
    if not UI_PID_FILE.exists():
        print("[!] WebUI 服务未运行。")
        return
    try:
        with open(UI_PID_FILE, "r") as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGTERM)
        time.sleep(0.5)
        print(f"[✅] WebUI 服务已停止 (PID: {pid})")
    except ProcessLookupError:
        print("[!] WebUI 进程已不存在，清理残留 PID 文件。")
    except Exception as e:
        print(f"[-] 停止 WebUI 失败: {e}")
    finally:
        UI_PID_FILE.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description="AWD 统一资产与状态管理工具 (SQLite awd.db + 5s 异步探活看门狗)")
    subparsers = parser.add_subparsers(dest="command")

    # 导入资产
    p_import = subparsers.add_parser("import", help="导入资产文本至数据库")
    p_import.add_argument("file", nargs="?", help="资产文本文件路径 (省略则从 stdin 读取)")
    p_import.add_argument("--my-ip", action="append", default=[], help="我方防守机 IP (可重复指定，打标为 self)")
    p_import.add_argument("--port", type=int, default=80, help="默认 Web 端口 (默认 80)")
    p_import.add_argument("--role", default="opponent", help="默认角色 (opponent 或 self)")

    # 录入单个资产 (支持标记我方防守机及存入 SSH 账号密码)
    p_add = subparsers.add_parser("add", help="录入单个资产 (支持参数化配置我方防守机及 SSH 账号密码)")
    p_add.add_argument("pos_ip", nargs="?", default=None, help="目标 IP (支持位置参数或 --ip)")
    p_add.add_argument("--ip", dest="opt_ip", default=None, help="目标 IP")
    p_add.add_argument("--port", type=int, default=80, help="Web 端口 (默认 80)")
    p_add.add_argument("--app", default="web", help="题型/服务标识 (默认 web)")
    p_add.add_argument("--role", default="opponent", choices=["opponent", "self"], help="角色: self(我方) 或 opponent(对手)")
    p_add.add_argument("--self", dest="is_self", action="store_true", help="快捷标记为我方防守资产")
    p_add.add_argument("--ssh-port", type=int, default=22, help="SSH 端口 (默认 22)")
    p_add.add_argument("--user", "--ssh-user", dest="ssh_user", default="ctf", help="SSH 用户名 (默认 ctf)")
    p_add.add_argument("--pass", "--password", "--ssh-pass", dest="ssh_pass", help="SSH 密码")
    p_add.add_argument("--key", "--key-file", "--ssh-key", dest="ssh_key", help="SSH 私钥路径")
    p_add.add_argument("--db", default=DB_PATH, help="指定数据库路径")

    # 录入裁判平台/Flag提交服务器资产 (role='server')
    p_add_server = subparsers.add_parser("add-server", help="录入裁判平台/Flag提交服务器资产 (role='server')")
    p_add_server.add_argument("url", help="裁判平台接口 URL (如 http://10.0.0.1/get_flag?token=xxx)")
    p_add_server.add_argument("--name", default="flag_server", help="平台资产名称 (默认 flag_server)")
    p_add_server.add_argument("--db", default=DB_PATH, help="指定数据库路径")

    # 比赛全局配置管理 (flag_server, token 等)
    p_config = subparsers.add_parser("config", help="查看或设置比赛配置 (flag_server, token, round 等)")
    p_config.add_argument("key", nargs="?", help="配置项名称 (如 flag_server, token)")
    p_config.add_argument("value", nargs="?", help="配置项数值 (若省略则为查询该配置)")
    p_config.add_argument("--db", default=DB_PATH, help="指定数据库路径")

    # 清理与重置表 (归零自增 ID)
    p_clean = subparsers.add_parser("clean", help="清空数据表并重置自增 ID 序列为 1 (vulns / flags / targets / all)")
    p_clean.add_argument("table", nargs="?", default="all", choices=["vulns", "flags", "targets", "backdoors", "shell", "all"], help="要清理的表 (默认 all)")
    p_clean.add_argument("--db", default=DB_PATH, help="指定数据库路径")

    # 守护进程管理
    p_start = subparsers.add_parser("start", help="启动 5s 异步探活看门狗 (后台常驻)")
    p_start.add_argument("--interval", type=int, default=5, help="探活轮询周期秒数 (默认 5s)")

    subparsers.add_parser("stop", help="停止后台探活看门狗")
    subparsers.add_parser("status", help="查看数据库态势与存活看板")

    # 供攻击脚本提取 URL
    p_urls = subparsers.add_parser("urls", help="提取当前存活的目标 URL 列表")
    p_urls.add_argument("--app", help="过滤题型名称")
    p_urls.add_argument("--role", default="opponent", help="过滤角色 (默认 opponent)")

    # 快捷直接查询单一类型
    p_query = subparsers.add_parser("query", help="直接按单一类型查询 (题型名如 seacms / self / vulns / flags / apps)")
    p_query.add_argument("type", nargs="?", default="apps", help="查询目标类型: 题型名(seacms)、self(我方)、vulns(漏洞)、flags(战果)、apps(概览)")
    p_query.add_argument("sub", nargs="?", help="二级过滤标识 (如 query vulns seacms)")
    p_query.add_argument("--all", action="store_true", help="显示全部 (默认查题型时仅显示存活对手)")
    p_query.add_argument("--urls", action="store_true", help="仅输出 URL 列表 (适合管道给攻击脚本)")
    p_query.add_argument("--ips", action="store_true", help="仅输出 IP 列表")
    p_query.add_argument("--json", action="store_true", help="以 JSON 格式输出")
    p_query.add_argument("--db", default=DB_PATH, help="指定数据库路径")

    # WebUI 态势大盘管理
    p_ui = subparsers.add_parser("ui", help="启动 WebUI 态势大盘 (127.0.0.1:8090)")
    p_ui.add_argument("--port", type=int, default=UI_PORT, help="Web 端口 (默认 8090)")

    subparsers.add_parser("ui-stop", help="停止后台 WebUI 服务")

    # 内部后台执行入口
    p_run_ui = subparsers.add_parser("run-ui")
    p_run_ui.add_argument("--port", type=int, default=UI_PORT)

    p_daemon = subparsers.add_parser("run-daemon")
    p_daemon.add_argument("--interval", type=int, default=5)

    args = parser.parse_args()

    # 自动保障机制：在调用资产管理技能的任何常规功能时，若 WebUI 未运行则自动拉起后台服务
    if args.command not in ["run-ui", "run-daemon", "stop", "ui-stop", None]:
        ensure_ui_running()

    if args.command == "import":
        if args.file and os.path.exists(args.file):
            with open(args.file, "r", encoding="utf-8") as f:
                content = f.read()
        elif not sys.stdin.isatty():
            content = sys.stdin.read()
        else:
            print("[-] 请提供资产文件路径或通过管道输入。")
            sys.exit(1)
        count = import_assets_text(content, my_ips=args.my_ip, default_port=args.port, role_default=args.role)
        print(f"[+] 成功录入/更新 {count} 条资产记录至 {DB_PATH}")
        sync_to_awd_red(args.db)
        show_status()

    elif args.command == "add":
        target_ip = args.pos_ip or args.opt_ip
        if not target_ip:
            print("[-] 请指定目标 IP，例如: add 192.168.1.50 --self 或 add --ip 192.168.1.50")
            sys.exit(1)
        role = "self" if (args.is_self or args.role == "self") else "opponent"
        cmd_add(
            ip=target_ip,
            port=args.port,
            role=role,
            app=args.app,
            ssh_port=args.ssh_port,
            ssh_user=args.ssh_user,
            ssh_pass=args.ssh_pass,
            ssh_key=args.ssh_key,
            db_path=args.db
        )
        sync_to_awd_red(args.db)

    elif args.command == "add-server":
        cmd_add_server(url=args.url, name=args.name, db_path=args.db)

    elif args.command == "config":
        cmd_config(key=args.key, value=args.value, db_path=args.db)

    elif args.command == "clean":
        cmd_clean(target_table=args.table, db_path=args.db)

    elif args.command == "start":
        start_daemon_background(interval=args.interval)

    elif args.command == "stop":
        stop_daemon()

    elif args.command == "status":
        show_status()

    elif args.command == "urls":
        live_urls = get_live_urls(app=args.app, role=args.role)
        for u in live_urls:
            print(u)

    elif args.command == "query":
        cmd_query(
            target_type=args.type,
            filter_sub=args.sub,
            show_all=args.all,
            urls_only=args.urls,
            ips_only=args.ips,
            as_json=args.json,
            db_path=args.db
        )

    elif args.command == "ui":
        start_ui_background(port=args.port)

    elif args.command == "ui-stop":
        stop_ui()

    elif args.command == "run-ui":
        run_ui_process(port=args.port)

    elif args.command == "run-daemon":
        run_daemon_process(interval=args.interval)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
