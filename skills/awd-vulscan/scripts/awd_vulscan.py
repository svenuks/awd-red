#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
awd-vulscan: AWD 源码漏洞审计与轻量探活工具
集成内嵌 D盾 引擎，纯 JSON 架构，自动关联 awd-platform 资产与备份。
"""

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
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
AWD_RED_DB = AWD_RED_DIR / "data" / "platform.db"
AWD_RED_VULNS_JSON = AWD_RED_DIR / "data" / "vulns.json"
AWD_RED_API_URL = os.environ.get("AWD_RED_API_URL", "http://127.0.0.1:8800/api/vulns")
BACKUP_DIR = Path(os.environ.get("AWD_BACKUP_DIR", str(Path.cwd() / "awd_backups")))

PLATFORM_DATA_DIR = AWD_RED_DIR / "data"
PLATFORM_TARGETS_FILE = AWD_RED_DIR / "config" / "targets.txt"
PLATFORM_VULNS_FILE = PLATFORM_DATA_DIR / "vulns.json"
PLATFORM_RUN_DIR = AWD_RED_DIR / "logs"
DEFAULT_OUT_DIR = PLATFORM_RUN_DIR / "vuln"


def find_default_ssh_key() -> str:
    """Finds default local private key."""
    ssh_dir = Path.home() / ".ssh"
    for candidate in ["id_ed25519", "id_rsa"]:
        priv = ssh_dir / candidate
        if priv.exists() and (ssh_dir / f"{candidate}.pub").exists():
            return str(priv)
    return ""


def load_self_targets_from_platform() -> list:
    """Loads self targets from awd.db or awd-platform targets.json."""
    targets = []
    # 1. 优先读取 awd.db
    db_candidates = [
        AWD_RED_DIR / "skills" / "awd-asset" / "data" / "awd.db",
        Path.home() / ".agents" / "skills" / "awd-asset" / "data" / "awd.db",
        AWD_RED_DB
    ]
    for db_path in db_candidates:
        if db_path.exists():
            try:
                conn = sqlite3.connect(str(db_path))
                conn.row_factory = sqlite3.Row
                rows = conn.execute("SELECT ip, port, ssh_port, ssh_user, ssh_pass, ssh_key FROM targets WHERE role='self'").fetchall()
                conn.close()
                for r in rows:
                    targets.append(dict(r))
                if targets:
                    return targets
            except Exception:
                pass

    # 2. 回退到 targets.json
    if PLATFORM_TARGETS_FILE.exists():
        try:
            with open(PLATFORM_TARGETS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return [t for t in data if t.get("role") == "self"]
        except Exception:
            pass

    return targets


def pull_self_target_code(host: str, port: int = 22, user: str = "ctf", password: str = "", key_path: str = "", custom_web_dir: str = "", out_dir: Path = BACKUP_DIR) -> dict:
    """Pulls source code from self machine via Paramiko (password/key) or system SSH/rsync."""
    print(f"\n[*] [阶段 1/2: 极速拉取源码] 目标: {user}@{host}:{port}...")

    local_host_dir = out_dir / host
    local_html_dir = local_host_dir / "html"
    local_html_dir.mkdir(parents=True, exist_ok=True)

    # 1. 尝试使用 Paramiko (最兼容密码和私钥，免外部依赖)
    try:
        import paramiko
        import tarfile
        import io

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kwargs = {
            "hostname": host,
            "port": int(port),
            "username": user,
            "timeout": 8,
            "banner_timeout": 8
        }
        if password:
            connect_kwargs["password"] = password
        elif key_path and os.path.exists(key_path):
            connect_kwargs["key_filename"] = key_path
        else:
            default_key = find_default_ssh_key()
            if default_key:
                connect_kwargs["key_filename"] = default_key

        ssh.connect(**connect_kwargs)

        # 探测 Web 目录
        check_script = "for d in /var/www/html /var/www /app /home/ctf/web /home/ctf/html /www; do [ -d \"$d\" ] && [ $(ls -A \"$d\" 2>/dev/null | wc -l) -gt 0 ] && echo \"$d\" && exit 0; done"
        _, stdout, _ = ssh.exec_command(check_script, timeout=5)
        detected_lines = stdout.read().decode("utf-8", errors="ignore").strip().splitlines()
        web_dir = custom_web_dir or (detected_lines[0] if detected_lines else "/var/www/html")

        # 使用 tar 流式压缩极速传输
        tar_cmd = f"tar -czf - -C '{web_dir}' . 2>/dev/null"
        _, stdout, _ = ssh.exec_command(tar_cmd, timeout=25)
        tar_bytes = stdout.read()
        ssh.close()

        if tar_bytes and len(tar_bytes) > 100:
            tar_stream = io.BytesIO(tar_bytes)
            with tarfile.open(fileobj=tar_stream, mode="r:gz") as tar:
                tar.extractall(path=local_html_dir)
            file_count = sum(len(files) for _, _, files in os.walk(local_html_dir))
            print(f"[+] 源码极速拉取成功！本地路径: {local_html_dir} (文件数: {file_count})")
            return {"host": host, "status": "success", "local_html": str(local_html_dir), "file_count": file_count}
    except Exception as e:
        print(f"[*] Paramiko 拉取未完成 ({e})，尝试系统 SSH/rsync 备选...")

    # 2. 回退使用系统 rsync / ssh
    key = key_path or find_default_ssh_key()
    if key and Path(key).exists():
        rsync_opt = f"ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p {port} -i {key}"
        rsync_cmd = ["rsync", "-az", "--delete", "-e", rsync_opt, f"{user}@{host}:/var/www/html/", str(local_html_dir) + "/"]
        try:
            r = subprocess.run(rsync_cmd, capture_output=True, text=True, timeout=25)
            if r.returncode == 0:
                file_count = sum(len(files) for _, _, files in os.walk(local_html_dir))
                print(f"[+] 自机源码拉取完成 (rsync)！本地路径: {local_html_dir} (文件数: {file_count})")
                return {"host": host, "status": "success", "local_html": str(local_html_dir), "file_count": file_count}
        except Exception:
            pass

    file_count = sum(len(files) for _, _, files in os.walk(local_html_dir))
    if file_count > 0:
        return {"host": host, "status": "success", "local_html": str(local_html_dir), "file_count": file_count}

    print(f"[-] 警告: 无法从 {host} 自动拉取源码，请检查 SSH 凭据。")
    return {"host": host, "status": "failed", "error": "Pull failed"}


def find_dshield_bin() -> Path:
    """Locate embedded or system dshield executable."""
    script_dir = Path(__file__).resolve().parent
    candidates = [
        script_dir.parent / "tools" / "dshield" / "dshield",
        Path.home() / "tools" / "dshield" / "dshield",
    ]
    custom_dshield = os.environ.get("DSHIELD_BIN")
    if custom_dshield:
        candidates.insert(0, Path(custom_dshield))
    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return c.resolve()
    return None


def find_latest_backup_dir() -> Path:
    """Finds the newest extracted web root from awd_backups."""
    if not BACKUP_DIR.exists():
        return None
    # Sort host dirs by mtime first (to catch newest backup folders)
    host_dirs = [p for p in BACKUP_DIR.iterdir() if p.is_dir() and not p.name.startswith(".")]
    if host_dirs:
        host_dirs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        for h in host_dirs:
            html_p = h / "html"
            if html_p.is_dir():
                return html_p
        return host_dirs[0]

    return None


def get_self_target_url() -> str:
    """Reads self target URL from platform targets.json."""
    if not PLATFORM_TARGETS_FILE.exists():
        return ""
    try:
        with open(PLATFORM_TARGETS_FILE, "r", encoding="utf-8") as f:
            targets = json.load(f)
            for t in targets:
                if t.get("role") == "self":
                    url = t.get("target_url")
                    if url:
                        return url.rstrip("/")
                    ip = t.get("ip")
                    port = t.get("port", 80)
                    return f"http://{ip}:{port}"
    except Exception:
        pass
    return ""


def extract_archive_if_needed(target_path):
    path = Path(target_path).resolve()
    if path.is_dir():
        return path, None

    if not path.is_file():
        raise FileNotFoundError(f"目标不存在: {target_path}")

    temp_dir = tempfile.mkdtemp(prefix="awd_vulscan_extract_")
    print(f"[*] 检测到压缩包，正在解包至临时目录: {temp_dir} ...")

    if tarfile.is_tarfile(path):
        with tarfile.open(path, "r:*") as tar:
            tar.extractall(path=temp_dir)
        return Path(temp_dir), temp_dir
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path, "r") as zf:
            zf.extractall(path=temp_dir)
        return Path(temp_dir), temp_dir
    else:
        raise ValueError(f"不支持的归档格式: {target_path}")


def classify_finding(finding_type, file_content):
    t_lower = (finding_type or "").lower()
    c_lower = (file_content or "").lower()

    if any(k in t_lower for k in ["一句话", "大马", "后门", "webshell"]):
        return "backdoor"
    elif "eval" in t_lower or "eval" in c_lower:
        return "eval"
    elif "assert" in t_lower or "assert" in c_lower:
        return "assert"
    elif any(k in t_lower for k in ["执行", "exec", "system", "shell"]) or any(k in c_lower for k in ["system(", "shell_exec(", "passthru(", "exec("]):
        return "cmd"
    elif any(k in t_lower for k in ["引用", "包含", "include", "require"]) or "include" in c_lower:
        return "lfi"
    elif any(k in t_lower for k in ["file_put", "写文件", "生成脚本"]) or "file_put_contents" in c_lower:
        return "write"
    return "suspicious"


def extract_code_snippet(file_path, line_number=None, context_lines=3):
    if not os.path.isfile(file_path):
        return "", []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return "", []

    params = []
    param_matches = re.findall(r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\[['\"]?([a-zA-Z0-9_\-]+)['\"]?\]", "".join(lines))
    for method, p_name in param_matches:
        params.append(f"{method}:{p_name}")

    if line_number and 1 <= line_number <= len(lines):
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        snippet_lines = []
        for idx in range(start, end):
            prefix = ">> " if idx == (line_number - 1) else "   "
            snippet_lines.append(f"{prefix}{idx + 1}: {lines[idx].rstrip()}")
        snippet = "\n".join(snippet_lines)
    else:
        snippet = "\n".join(lines[:15])

    return snippet, list(set(params))


def generate_poc_hint(kind, params, rel_file):
    main_param = "cmd"
    method = "POST"
    if params:
        p_first = params[0]
        if ":" in p_first:
            m, p = p_first.split(":", 1)
            method = m if m in ["GET", "POST"] else "POST"
            main_param = p

    if kind in ["backdoor", "eval", "assert"]:
        return f"curl -X {method} 'http://<target>/{rel_file}' -d '{main_param}=phpinfo();'"
    elif kind == "cmd":
        return f"curl -X {method} 'http://<target>/{rel_file}' -d '{main_param}=id'"
    elif kind == "lfi":
        return f"curl 'http://<target>/{rel_file}?{main_param}=/etc/passwd'"
    elif kind == "write":
        return f"curl -X {method} 'http://<target>/{rel_file}' -d '{main_param}=1'"
    return f"check parameters on {rel_file}"


def run_dshield_scan(dshield_bin, scan_dir, min_level=3):
    """Executes dshield scan with native json output."""
    cmd = [
        str(dshield_bin),
        "scan",
        str(scan_dir),
        "--format", "json",
        "--min-level", str(min_level)
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="ignore")
    raw_output = proc.stdout
    findings = []
    seen = set()

    try:
        data = json.loads(raw_output)
        for item in data.get("findings", []):
            rel_file = item.get("file", "")
            fpath = os.path.join(str(scan_dir), rel_file) if not os.path.isabs(rel_file) else rel_file
            level = int(item.get("level", 3))
            vtype = item.get("type", "Unknown")
            line_no = item.get("line")

            key = (rel_file, line_no, vtype)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "level": level,
                    "type": vtype,
                    "file": fpath,
                    "rel_file": rel_file,
                    "line": line_no,
                    "evidence": item.get("evidence", [])
                })
        return findings, raw_output
    except Exception as e:
        # Fallback to regex parsing if json decode fails
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            m = re.match(r"^\[(\d+)\]\s+\[(.*?)\]\s+(.*?)(?:\s+(\d+))?$", line)
            if m:
                level = int(m.group(1))
                vtype = m.group(2).strip()
                fpath = m.group(3).strip()
                line_no = int(m.group(4)) if m.group(4) else None
                key = (fpath, line_no, vtype)
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "level": level,
                        "type": vtype,
                        "file": fpath,
                        "rel_file": os.path.relpath(fpath, scan_dir),
                        "line": line_no,
                        "evidence": []
                    })
        return findings, raw_output


def verify_vuln_entry(base_url, vuln, timeout=2.5, probe_type="token"):
    clean_base = base_url.rstrip("/")
    rel_file = vuln["file"].lstrip("/")
    url = f"{clean_base}/{rel_file}"
    params = vuln.get("params", [])
    token = f"probe_ok_{int(time.time()*1000)}"

    method = "POST"
    param_name = "cmd"
    if params:
        p_first = params[0]
        if ":" in p_first:
            m, p = p_first.split(":", 1)
            method = m if m in ["GET", "POST"] else "POST"
            param_name = p

    try:
        headers = {"User-Agent": "Mozilla/5.0 (AWD-VulScan-Verify/1.0)"}
        payload = f"echo '{token}';"
        if method == "POST":
            data = urllib.parse.urlencode({param_name: payload}).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers=headers)
        else:
            sep = "&" if "?" in url else "?"
            full_url = f"{url}{sep}{param_name}={urllib.parse.quote(payload)}"
            req = urllib.request.Request(full_url, headers=headers)

        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            if token in body:
                return {"verified": True, "url": url, "param": param_name, "evidence": token}
    except Exception:
        pass

    return {"verified": False, "url": url, "param": param_name, "evidence": ""}


def save_vulns_to_json(vulns: list, clean: bool = False) -> int:
    """Atomic write to platform vulns and sync to AWD-Red platform."""
    # 1. 同步推送到 AWD-Red 新平台 SQLite 数据库
    if AWD_RED_DB.exists():
        try:
            import sqlite3
            conn = sqlite3.connect(str(AWD_RED_DB), timeout=10.0)
            with conn:
                if clean:
                    conn.execute("DELETE FROM vulns")
                for v in vulns:
                    app = v.get("app", "web")
                    file_path = v.get("file", "")
                    line = v.get("line", 1)
                    level = v.get("level", 3)
                    vuln_type = v.get("vuln_type", v.get("type", "Unknown"))
                    category = v.get("category", "")
                    param = v.get("param", "")
                    poc_hint = v.get("poc_hint", "")
                    verified = 1 if v.get("verified") else 0
                    status = v.get("status", "active")
                    conn.execute("""
                        INSERT INTO vulns (app, file, line, level, vuln_type, category, param, poc_hint, verified, status, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                        ON CONFLICT(app, file, line, param) DO UPDATE SET
                            level = excluded.level,
                            vuln_type = excluded.vuln_type,
                            category = excluded.category,
                            poc_hint = excluded.poc_hint,
                            verified = excluded.verified,
                            status = excluded.status,
                            updated_at = CURRENT_TIMESTAMP
                    """, (app, file_path, line, level, vuln_type, category, param, poc_hint, verified, status))
            conn.close()
            print(f"[+] 已同步写入 AWD-Red 平台 SQLite 漏洞库: {AWD_RED_DB}")
        except Exception as e:
            print(f"[-] 写入 AWD-Red SQLite 异常: {e}")

    # 2. 尝试向正在运行的 AWD-Red Web 服务推送 HTTP API
    try:
        req_data = json.dumps({"vulns": vulns, "clean": clean}).encode("utf-8")
        req = urllib.request.Request(
            AWD_RED_API_URL,
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            if resp.status == 200:
                print(f"[+] 已通过 HTTP API 实时推送到 AWD-Red Web 控制台")
    except Exception:
        # Web 服务若未启动则静默跳过
        pass

    # 3. 写入 AWD-Red 数据目录下的 JSON 备份
    try:
        AWD_RED_VULNS_JSON.parent.mkdir(parents=True, exist_ok=True)
        with open(AWD_RED_VULNS_JSON, "w", encoding="utf-8") as f:
            json.dump(vulns, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

    # 4. 同时向后兼容原 awd-platform
    PLATFORM_DATA_DIR.mkdir(parents=True, exist_ok=True)
    existing = []
    if not clean and PLATFORM_VULNS_FILE.exists():
        try:
            with open(PLATFORM_VULNS_FILE, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            existing = []

    if clean:
        existing = []

    seen = {f"{v.get('app')}:{v.get('file')}:{v.get('line')}": v for v in existing}
    next_id = max([v.get("id", 0) for v in existing] or [0]) + 1

    for v in vulns:
        key = f"{v.get('app')}:{v.get('file')}:{v.get('line')}"
        if key in seen:
            seen[key].update(v)
        else:
            v["id"] = next_id
            next_id += 1
            existing.append(v)
            seen[key] = v

    tmp = PLATFORM_VULNS_FILE.with_suffix(f".tmp.{os.getpid()}")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)
    tmp.replace(PLATFORM_VULNS_FILE)
    return len(existing)


def run_audit(target, app=None, min_level=3, out_dir=str(DEFAULT_OUT_DIR), clean=False, verify=True, target_url=None, probe_type="token"):
    dshield_bin = find_dshield_bin()
    if not dshield_bin:
        raise RuntimeError("未能定位 D盾 可执行文件 (tools/dshield/dshield)")

    real_path, cleanup_dir = extract_archive_if_needed(target)
    scan_dir = real_path.resolve()
    app_name = app or real_path.name
    if app_name.lower() in ["html", "web", "www"]:
        parent_name = real_path.parent.name
        if parent_name and parent_name not in ["/", ".", "awd_backups"]:
            app_name = parent_name

    print(f"[*] 开始 D盾 源码安全审计: {scan_dir} (应用标识: {app_name}) ...")
    raw_findings, _ = run_dshield_scan(dshield_bin, scan_dir, min_level=min_level)

    filtered = [f for f in raw_findings if f["level"] >= min_level]
    print(f"[+] D盾扫描完成: 原始检出 {len(raw_findings)} 项，等级>={min_level} 的高危项共 {len(filtered)} 条")

    enriched = []
    for idx, f in enumerate(filtered, start=1):
        fpath = f["file"]
        rel_path = f.get("rel_file") or os.path.relpath(fpath, scan_dir)
        snippet, params = extract_code_snippet(fpath, f.get("line"))
        category = classify_finding(f.get("type"), snippet)
        poc_hint = generate_poc_hint(category, params, rel_path)

        clean_param = ""
        if params:
            first_p = params[0]
            clean_param = first_p.split(":")[-1] if ":" in first_p else first_p

        enriched.append({
            "id": idx,
            "app": app_name,
            "file": rel_path,
            "line": f.get("line"),
            "level": f.get("level"),
            "vuln_type": f.get("type"),
            "category": category,
            "params": params,
            "param": clean_param,
            "poc_hint": poc_hint,
            "verified": False,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S")
        })

    # Cleanup temp archive extract if any
    if cleanup_dir and os.path.exists(cleanup_dir):
        shutil.rmtree(cleanup_dir, ignore_errors=True)

    # Verification phase
    if verify and enriched:
        actual_url = target_url or get_self_target_url()
        if actual_url:
            print(f"[*] 执行自机存活探活验证 (目标: {actual_url}) ...")
            v_count = 0
            for v in enriched:
                res = verify_vuln_entry(actual_url, v, probe_type=probe_type)
                v["verified"] = res["verified"]
                if res["verified"]:
                    v_count += 1
                    print(f"  [🟢 存活有效] {v['file']}:{v['line']} ({v['category']}) 入参: {res['param']}")
            print(f"[+] 探活验证完毕: 共 {len(enriched)} 项，成功验证存活 {v_count} 个！\n")
        else:
            print("[*] 平台中无存活自机 URL，跳过探活验证。")

    # Local files
    os.makedirs(out_dir, exist_ok=True)
    local_json = os.path.join(out_dir, "vulns.json")
    with open(local_json, "w", encoding="utf-8") as f:
        json.dump(enriched, f, indent=2, ensure_ascii=False)

    # Save to platform vulns.json (Pure JSON)
    total_saved = save_vulns_to_json(enriched, clean=clean)

    print(f"[✅] 审计分析完毕！")
    print(f"  - 发现风险项: {len(enriched)} 条")
    print(f"  - 平台 JSON 库: {PLATFORM_VULNS_FILE} (库中现有 {total_saved} 条记录)")
    print(f"  - 本地归档: {local_json}\n")

    return enriched


def main():
    parser = argparse.ArgumentParser(description="AWD 源码拉取与漏洞审计分析工具 (awd-vulscan)")
    parser.add_argument("target", nargs="?", default=None, help="源码目录路径或 web_xxx.tar.gz (缺省自动从自机免密拉取代码)")
    parser.add_argument("--host", help="自机/靶机 IP (直接快速拉取代码)")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH 端口 (默认 22)")
    parser.add_argument("--user", default="ctf", help="SSH 用户名 (默认 ctf)")
    parser.add_argument("--pass", "--password", dest="password", default="", help="SSH 密码")
    parser.add_argument("--key", default="", help="SSH 私钥路径")
    parser.add_argument("--app", help="应用名称 (缺省自动提取)")
    parser.add_argument("--min-level", type=int, choices=[2, 3, 4, 5], default=3, help="最低告警等级 (默认 3)")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR), help="分析产物输出目录 (默认: awd-platform/run/vuln)")
    parser.add_argument("--clean", action="store_true", help="写入前清空旧漏洞记录")
    parser.add_argument("--verify", action="store_true", default=True, help="对识别出的后门进行轻量存活验证 (默认开启)")
    parser.add_argument("--no-verify", dest="verify", action="store_false", help="关闭探活验证")
    parser.add_argument("--target-url", help="探活验证目标靶机基础 URL (缺省自动读取平台自机)")
    parser.add_argument("--pull-only", action="store_true", help="仅执行免密拉取自机代码，不进行后续审计")
    parser.add_argument("--no-pull", action="store_true", help="跳过自动拉取，仅对本地现有目录进行扫描")
    parser.add_argument("--json", action="store_true", help="终端输出 JSON 格式")

    args = parser.parse_args()

    target = args.target

    # 阶段 1: 若指定了 --host 或未指定本地目标且允许自动拉取
    if args.host:
        pull_res = pull_self_target_code(
            host=args.host,
            port=args.ssh_port,
            user=args.user,
            password=args.password,
            key_path=args.key
        )
        if pull_res.get("status") == "success":
            target = pull_res.get("local_html")
        if args.pull_only:
            print(f"[✅] 自机代码拉取完成 (--pull-only)。")
            return

    elif not target and not args.no_pull:
        self_targets = load_self_targets_from_platform()
        if self_targets:
            for st in self_targets:
                pull_res = pull_self_target_code(
                    host=st["ip"],
                    port=int(st.get("ssh_port", 22)),
                    user=st.get("ssh_user", "ctf"),
                    password=st.get("ssh_pass", ""),
                    key_path=st.get("ssh_key") or find_default_ssh_key()
                )
                if pull_res.get("status") == "success":
                    target = pull_res.get("local_html")
                    break

            if args.pull_only:
                print(f"[✅] 自机代码拉取完成 (--pull-only)。")
                return

    # 若未拉取或不需要拉取，则自动探测已有备份
    if not target:
        latest = find_latest_backup_dir()
        if latest:
            target = str(latest)
            print(f"[*] 自动选择最新已有备份源码: {target}")
        else:
            for c in [Path("html"), Path("/var/www/html"), Path("awd_backups")]:
                if c.exists():
                    target = str(c)
                    print(f"[*] 自动定位源码目录: {target}")
                    break

    if not target or not Path(target).exists():
        print("[-] 错误: 未指定目标且无法拉取自机代码。请先通过 awd-ctl add 录入自机或指定本地路径。")
        sys.exit(1)

    print(f"\n[*] [阶段 2/2: D盾源码安全审计] 目标路径: {target}")
    results = run_audit(
        target=target,
        app=args.app,
        min_level=args.min_level,
        out_dir=args.out_dir,
        clean=args.clean,
        verify=args.verify,
        target_url=args.target_url
    )

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
