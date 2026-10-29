"""
Database manager for AWD-Red platform.
Uses SQLite with Write-Ahead Logging (WAL) for high-performance concurrent logging.
"""

import os
import sqlite3
import hashlib
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "platform.db")

def get_db_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=20.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn

def init_db():
    conn = get_db_connection()
    with conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS pocs (
            name TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ready', -- ready, disabled, failed
            version INTEGER DEFAULT 1,
            description TEXT DEFAULT '',
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS rounds (
            round_num INTEGER PRIMARY KEY,
            start_time TEXT NOT NULL,
            end_time TEXT,
            status TEXT NOT NULL DEFAULT 'running', -- running, completed, skipped
            total_tasks INTEGER DEFAULT 0,
            success_tasks INTEGER DEFAULT 0,
            flags_found INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            round_num INTEGER NOT NULL,
            poc_name TEXT NOT NULL,
            target_ip TEXT NOT NULL,
            status TEXT NOT NULL, -- running, success, failed, timeout
            exit_code INTEGER,
            stdout TEXT,
            stderr TEXT,
            flag_captured TEXT,
            duration_ms INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS flags (
            flag_hash TEXT PRIMARY KEY,
            flag_val TEXT NOT NULL,
            round_num INTEGER NOT NULL,
            poc_name TEXT NOT NULL,
            target_ip TEXT NOT NULL,
            submit_status TEXT NOT NULL DEFAULT 'pending', -- pending, success, failed, duplicate, skipped
            submit_response TEXT,
            found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            submitted_at TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS vulns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app TEXT DEFAULT 'web',
            file TEXT NOT NULL,
            line INTEGER DEFAULT 1,
            level INTEGER DEFAULT 3,
            vuln_type TEXT NOT NULL,
            category TEXT,
            param TEXT,
            poc_hint TEXT,
            verified INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active', -- active, exploited, patched
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(app, file, line, param)
        );

        CREATE INDEX IF NOT EXISTS idx_tasks_round ON tasks(round_num);
        CREATE INDEX IF NOT EXISTS idx_tasks_poc ON tasks(poc_name);
        CREATE INDEX IF NOT EXISTS idx_flags_round ON flags(round_num);
        CREATE INDEX IF NOT EXISTS idx_flags_status ON flags(submit_status);
        CREATE INDEX IF NOT EXISTS idx_vulns_verified ON vulns(verified);
        CREATE INDEX IF NOT EXISTS idx_vulns_level ON vulns(level);
        """)
    conn.close()

class Database:
    @staticmethod
    def get_setting(key: str, default: Any = None) -> Any:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM system_settings WHERE key = ?", (key,))
        row = cursor.fetchone()
        conn.close()
        if row and row["value"] is not None:
            try:
                return json.loads(row["value"])
            except Exception:
                return row["value"]
        return default

    @staticmethod
    def set_setting(key: str, value: Any):
        conn = get_db_connection()
        val_str = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
        with conn:
            conn.execute(
                "INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
                (key, val_str)
            )
        conn.close()

    @staticmethod
    def register_or_update_poc(name: str, filename: str, filepath: str, file_hash: str, status: str = "ready") -> bool:
        """Returns True if updated/created, False if hash and status identical."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT file_hash, version, status, filepath FROM pocs WHERE name = ?", (name,))
        row = cursor.fetchone()
        updated = False
        try:
            with conn:
                if not row:
                    conn.execute(
                        "INSERT INTO pocs (name, filename, filepath, file_hash, status, version) VALUES (?, ?, ?, ?, ?, 1)",
                        (name, filename, filepath, file_hash, status)
                    )
                    updated = True
                else:
                    new_ver = row["version"] + 1 if row["file_hash"] != file_hash else row["version"]
                    if row["file_hash"] != file_hash or row["status"] != status or row["filepath"] != filepath:
                        conn.execute(
                            "UPDATE pocs SET filename = ?, filepath = ?, file_hash = ?, status = ?, version = ?, updated_at = CURRENT_TIMESTAMP WHERE name = ?",
                            (filename, filepath, file_hash, status, new_ver, name)
                        )
                        updated = True
        finally:
            conn.close()
        return updated

    @staticmethod
    def set_poc_status(name: str, status: str):
        conn = get_db_connection()
        with conn:
            conn.execute("UPDATE pocs SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE name = ?", (status, name))
        conn.close()

    @staticmethod
    def delete_poc(name: str):
        conn = get_db_connection()
        with conn:
            conn.execute("DELETE FROM pocs WHERE name = ?", (name,))
        conn.close()

    @staticmethod
    def clear_all_pocs():
        conn = get_db_connection()
        with conn:
            conn.execute("DELETE FROM pocs")
        conn.close()

    @staticmethod
    def get_all_pocs() -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        query = """
            SELECT p.*,
                   COALESCE(t.call_count, 0) as call_count,
                   COALESCE(t.success_count, 0) as success_count,
                   COALESCE(t.flags_count, 0) as flags_count
            FROM pocs p
            LEFT JOIN (
                SELECT poc_name,
                       COUNT(*) as call_count,
                       SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as success_count,
                       SUM(CASE WHEN flag_captured IS NOT NULL AND flag_captured != '' THEN 1 ELSE 0 END) as flags_count
                FROM tasks
                GROUP BY poc_name
            ) t ON p.name = t.poc_name
            ORDER BY p.name ASC
        """
        cursor.execute(query)
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    @staticmethod
    def get_ready_pocs() -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pocs WHERE status = 'ready' ORDER BY name ASC")
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    @staticmethod
    def record_round_start(round_num: int, start_time: str):
        conn = get_db_connection()
        with conn:
            conn.execute(
                "INSERT OR IGNORE INTO rounds (round_num, start_time, status) VALUES (?, ?, 'running')",
                (round_num, start_time)
            )
        conn.close()

    @staticmethod
    def update_round_stats(round_num: int, total_tasks: int, success_tasks: int, flags_found: int, status: str = "completed"):
        conn = get_db_connection()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with conn:
            conn.execute(
                "UPDATE rounds SET total_tasks = ?, success_tasks = ?, flags_found = ?, status = ?, end_time = ? WHERE round_num = ?",
                (total_tasks, success_tasks, flags_found, status, now_str, round_num)
            )
        conn.close()

    @staticmethod
    def record_task(task_id: str, round_num: int, poc_name: str, target_ip: str,
                    status: str, exit_code: Optional[int], stdout: str, stderr: str,
                    duration_ms: int, flag_captured: Optional[str] = None):
        conn = get_db_connection()
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO tasks (id, round_num, poc_name, target_ip, status, exit_code, stdout, stderr, duration_ms, flag_captured) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (task_id, round_num, poc_name, target_ip, status, exit_code, stdout, stderr, duration_ms, flag_captured)
            )
        conn.close()

    @staticmethod
    def save_flag(flag_val: str, round_num: int, poc_name: str, target_ip: str) -> bool:
        """
        Saves a newly captured flag.
        Returns True if flag is novel (inserted), False if already exists (deduplicated).
        """
        flag_clean = flag_val.strip()
        flag_hash = hashlib.sha256(flag_clean.encode("utf-8")).hexdigest()
        conn = get_db_connection()
        try:
            with conn:
                conn.execute(
                    "INSERT INTO flags (flag_hash, flag_val, round_num, poc_name, target_ip, submit_status) "
                    "VALUES (?, ?, ?, ?, ?, 'pending')",
                    (flag_hash, flag_clean, round_num, poc_name, target_ip)
                )
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    @staticmethod
    def get_pending_flags() -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM flags WHERE submit_status = 'pending' ORDER BY found_at ASC")
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    @staticmethod
    def update_flag_submit_status(flag_hash: str, status: str, response_text: str):
        conn = get_db_connection()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with conn:
            conn.execute(
                "UPDATE flags SET submit_status = ?, submit_response = ?, submitted_at = ? WHERE flag_hash = ?",
                (status, response_text, now_str, flag_hash)
            )
        conn.close()

    @staticmethod
    def get_stats() -> Dict[str, Any]:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) as count FROM flags")
        total_flags = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) as count FROM flags WHERE submit_status = 'success'")
        submitted_success = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) as count FROM flags WHERE submit_status = 'pending'")
        pending_flags = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) as count FROM tasks")
        total_tasks = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) as count FROM tasks WHERE status = 'success'")
        success_tasks = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) as count FROM pocs WHERE status = 'ready'")
        ready_pocs = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) as count FROM pocs")
        total_pocs = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) as count FROM vulns")
        total_vulns = cursor.fetchone()["count"]

        cursor.execute("SELECT COUNT(*) as count FROM vulns WHERE verified = 1")
        verified_vulns = cursor.fetchone()["count"]

        conn.close()
        return {
            "total_flags": total_flags,
            "submitted_success": submitted_success,
            "pending_flags": pending_flags,
            "total_tasks": total_tasks,
            "success_tasks": success_tasks,
            "ready_pocs": ready_pocs,
            "total_pocs": total_pocs,
            "total_vulns": total_vulns,
            "verified_vulns": verified_vulns
        }

    @staticmethod
    def save_vulns_batch(vulns: List[Dict[str, Any]], clean: bool = False) -> int:
        """Batch inserts or updates vulnerabilities discovered by D-Shield / awd-vulscan."""
        conn = get_db_connection()
        inserted_or_updated = 0
        try:
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
                    inserted_or_updated += 1
            return inserted_or_updated
        finally:
            conn.close()

    @staticmethod
    def get_all_vulns(limit: int = 200) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM vulns ORDER BY verified DESC, level DESC, id DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    @staticmethod
    def delete_vuln(vuln_id: int):
        conn = get_db_connection()
        with conn:
            conn.execute("DELETE FROM vulns WHERE id = ?", (vuln_id,))
        conn.close()

    @staticmethod
    def clear_all_vulns():
        conn = get_db_connection()
        with conn:
            conn.execute("DELETE FROM vulns")
        conn.close()

    @staticmethod
    def clear_all_flags():
        conn = get_db_connection()
        with conn:
            conn.execute("DELETE FROM flags")
        conn.close()

    @staticmethod
    def get_recent_flags(limit: int = 50) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM flags ORDER BY found_at DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    @staticmethod
    def get_recent_tasks(limit: int = 50) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

# Initialize tables when imported
init_db()
