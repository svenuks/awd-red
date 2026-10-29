#!/usr/bin/env python3
"""
AWD-Red Automation Platform V1.0
Decoupled AI Vulnerability Research & Platform Task Execution Engine.
"""

import os
import sys
import json
import logging
import argparse
import asyncio
import time
from aiohttp import web

# Add root directory to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from core.db import Database, init_db
from core.poc_manager import PoCManager
from core.submitter import Submitter
from core.flag_manager import FlagManager
from core.task_manager import TaskManager
from core.scheduler import Scheduler
from core.config_parser import ConfigParser
from core.cron_manager import CronTaskManager

# Setup Logging
LOGS_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOGS_DIR, "platform.log")

log_handlers = [logging.FileHandler(LOG_FILE, encoding="utf-8")]
# 当在交互式终端前台运行时打印到控制台；当通过 start.sh / nohup 重定向运行时仅保留 FileHandler，杜绝日志重复输出双份
if sys.stdout.isatty():
    log_handlers.append(logging.StreamHandler(sys.stdout))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=log_handlers
)
logging.getLogger("aiohttp.access").setLevel(logging.WARNING)
logger = logging.getLogger("awd_app")

# Global Instances
poc_manager = PoCManager()
submitter = Submitter()
flag_manager = FlagManager(submitter)

# Load settings for task manager init
SETTINGS_PATH = os.path.join(BASE_DIR, "config", "settings.json")
def get_settings():
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "poc_concurrency": 64,
        "global_concurrency": 128,
        "task_timeout_sec": 3.0,
        "web_port": 8800,
        "web_host": "0.0.0.0"
    }

init_settings = get_settings()
task_manager = TaskManager(
    flag_manager=flag_manager,
    poc_concurrency=int(init_settings.get("poc_concurrency", 64)),
    global_concurrency=int(init_settings.get("global_concurrency", 128)),
    timeout_sec=float(init_settings.get("task_timeout_sec", 3.0))
)
scheduler = Scheduler(poc_manager, task_manager, flag_manager)
cron_manager = CronTaskManager(flag_manager=flag_manager, interval_seconds=600)

# ---------------- API Handlers ----------------

async def handle_index(request):
    html_path = os.path.join(BASE_DIR, "web", "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return web.Response(text=f.read(), content_type="text/html")

async def handle_status(request):
    settings = scheduler.load_settings()
    curr_round, sec_to_next, is_active = scheduler.calculate_round(settings)
    targets = scheduler.load_targets()
    stats = Database.get_stats()
    duration = int(settings.get("round_duration_sec", 600))
    elapsed_sec = max(0, duration - sec_to_next)
    progress_percent = min(100, int((elapsed_sec / duration) * 100)) if duration > 0 else 0

    data = {
        "current_round": curr_round,
        "seconds_to_next": sec_to_next,
        "elapsed_sec": elapsed_sec,
        "progress_percent": progress_percent,
        "is_active": is_active,
        "round_duration": duration,
        "scheduler_enabled": scheduler.enabled,
        "watcher_enabled": scheduler.watcher_enabled,
        "auto_trigger_on_new_poc": scheduler.auto_trigger_on_new_poc,
        "schedule_mode": scheduler.schedule_mode,
        "is_executing_round": scheduler.is_executing_round,
        "active_tasks": task_manager.active_tasks_count,
        "global_concurrency": task_manager.global_concurrency,
        "poc_concurrency": task_manager.poc_concurrency,
        "last_executed_round": scheduler.last_executed_round,
        "target_count": len(targets),
        "stats": stats
    }
    return web.json_response(data)

async def handle_flags(request):
    flags = Database.get_recent_flags(limit=100)
    return web.json_response(flags)

async def handle_flags_clear(request):
    flag_manager.clear_all()
    return web.json_response({
        "success": True,
        "message": "成功清空所有捕获的 Flag 记录与去重历史！"
    })

async def handle_tasks(request):
    tasks = Database.get_recent_tasks(limit=100)
    return web.json_response(tasks)

async def handle_pocs(request):
    pocs = Database.get_all_pocs()
    return web.json_response(pocs)

async def handle_pocs_sync(request):
    actions = poc_manager.scan_and_sync()
    return web.json_response(actions)

async def handle_pocs_toggle(request):
    data = await request.json()
    name = data.get("name")
    enable = data.get("enable", True)
    ok = poc_manager.toggle_poc(name, enable)
    return web.json_response({"success": ok, "name": name, "enabled": enable})

async def handle_pocs_clear(request):
    count = poc_manager.clear_all_pocs()
    return web.json_response({
        "success": True,
        "count": count,
        "message": f"成功清空所有 PoC 文件及数据库记录 (清理文件数: {count})"
    })

async def handle_pocs_delete(request):
    try:
        data = await request.json()
    except Exception:
        data = {}
    name = data.get("name")
    if not name:
        return web.json_response({"success": False, "error": "Missing poc name"}, status=400)
    ok = poc_manager.delete_single_poc(name)
    return web.json_response({"success": ok, "message": f"成功删除 PoC: {name}"})

async def handle_get_vulns(request):
    vulns = Database.get_all_vulns(limit=200)
    return web.json_response(vulns)

async def handle_save_vulns(request):
    try:
        data = await request.json()
    except Exception as e:
        return web.json_response({"success": False, "error": f"Invalid JSON: {e}"}, status=400)

    clean = False
    vuln_list = []
    if isinstance(data, list):
        vuln_list = data
    elif isinstance(data, dict):
        clean = data.get("clean", False)
        vuln_list = data.get("vulns", [data] if "file" in data else [])

    count = Database.save_vulns_batch(vuln_list, clean=clean)
    logger.info(f"Vulnerability Hub: Updated/recorded {count} vulnerability entries (clean={clean}).")
    return web.json_response({"success": True, "count": count, "message": f"成功录入/更新 {count} 条漏洞"})

async def handle_clear_vulns(request):
    Database.clear_all_vulns()
    return web.json_response({"success": True, "message": "漏洞库已清空"})

async def handle_get_settings(request):
    settings = scheduler.load_settings()
    target_path = os.path.join(BASE_DIR, "config", "targets.txt")
    raw_targets = []
    if os.path.exists(target_path):
        with open(target_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    raw_targets.append(line)
    expanded = ConfigParser.expand_all_targets(raw_targets)
    return web.json_response({
        "settings": settings,
        "targets": raw_targets,
        "expanded_count": len(expanded)
    })

async def handle_save_settings(request):
    data = await request.json()
    curr = scheduler.load_settings()
    curr.update(data)
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(curr, f, indent=2, ensure_ascii=False)

    # Apply live to task manager & flag manager
    task_manager.poc_concurrency = int(curr.get("poc_concurrency", 64))
    task_manager.timeout_sec = float(curr.get("task_timeout_sec", 3.0))
    if "flag_pattern" in curr:
        flag_manager.set_pattern(curr["flag_pattern"])

    return web.json_response({"success": True, "message": "参数已成功持久化并动态生效"})

async def handle_get_targets(request):
    target_path = os.path.join(BASE_DIR, "config", "targets.txt")
    raw_targets = []
    if os.path.exists(target_path):
        with open(target_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    raw_targets.append(line)
    expanded = ConfigParser.expand_all_targets(raw_targets)
    return web.json_response({
        "raw_targets": raw_targets,
        "expanded_targets": expanded,
        "count": len(expanded)
    })

async def handle_save_targets(request):
    data = await request.json()
    targets = data.get("targets", [])
    target_path = os.path.join(BASE_DIR, "config", "targets.txt")
    with open(target_path, "w", encoding="utf-8") as f:
        f.write("# AWD 目标靶机 IPv4 列表 (支持单IP、192.168.1.1-255及CIDR)\n")
        for t in targets:
            t = t.strip()
            if t:
                f.write(f"{t}\n")
    expanded = ConfigParser.expand_all_targets(targets)
    logger.info(f"Targets saved: {len(targets)} input rules, expanded into {len(expanded)} active targets")
    return web.json_response({
        "success": True,
        "message": f"成功保存配置，已自动展开并激活 {len(expanded)} 台目标靶机！",
        "expanded_count": len(expanded),
        "expanded_targets": expanded
    })

async def handle_expand_targets(request):
    data = await request.json()
    targets = data.get("targets", [])
    expanded = ConfigParser.expand_all_targets(targets)
    return web.json_response({
        "success": True,
        "expanded_targets": expanded,
        "count": len(expanded)
    })

async def handle_clear_targets(request):
    target_path = os.path.join(BASE_DIR, "config", "targets.txt")
    with open(target_path, "w", encoding="utf-8") as f:
        f.write("# AWD 目标靶机 IPv4 列表 (已清空)\n")
    logger.info("Cleared all targets in targets.txt")
    return web.json_response({
        "success": True,
        "message": "成功清空目标靶机 IPv4 列表！",
        "count": 0,
        "expanded_targets": []
    })

async def handle_get_submitter(request):
    cfg = submitter.load_config()
    return web.json_response(cfg)

async def handle_save_submitter(request):
    data = await request.json()
    sub_path = os.path.join(BASE_DIR, "config", "submitter.json")
    with open(sub_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    logger.info(f"Submitter config saved: enabled={data.get('enabled')}, url={data.get('url')}")
    return web.json_response({"success": True, "message": "提交器配置已成功保存！"})

async def handle_parse_submitter_raw(request):
    data = await request.json()
    raw_text = data.get("raw") or data.get("text") or ""
    parsed = ConfigParser.parse_request_package(raw_text)
    return web.json_response({"success": True, "config": parsed})

async def handle_import_submitter_raw(request):
    data = await request.json()
    raw_text = data.get("raw") or data.get("text") or ""
    parsed = ConfigParser.parse_request_package(raw_text)
    if not parsed.get("url"):
        return web.json_response({"success": False, "message": "未能从请求包中解析出有效的 URL，请检查格式！"})

    sub_path = os.path.join(BASE_DIR, "config", "submitter.json")
    with open(sub_path, "w", encoding="utf-8") as f:
        json.dump(parsed, f, indent=2, ensure_ascii=False)

    logger.info(f"Submitter config auto-imported from raw package: URL={parsed.get('url')}, Method={parsed.get('method')}")
    return web.json_response({
        "success": True,
        "config": parsed,
        "message": f"成功自动提取配置！已提取 {len(parsed.get('headers', {}))} 个请求头并设置 Flag 模板。"
    })

async def handle_test_submitter(request):
    data = await request.json()
    test_flag = data.get("flag", "flag{test_demo_flag_123456}")
    status, resp = await submitter.submit_flag(test_flag)
    return web.json_response({
        "success": status in ["success", "duplicate"],
        "status": status,
        "response": resp,
        "message": f"提交状态: {status} | 返回: {resp}"
    })

async def handle_resubmit_flags(request):
    data = {}
    try:
        data = await request.json()
    except Exception:
        pass
    flag_hash = data.get("flag_hash")
    if flag_hash:
        status, resp = await flag_manager.resubmit_flag(flag_hash)
        return web.json_response({
            "success": status in ["success", "duplicate"],
            "status": status,
            "response": resp,
            "message": f"Flag 重提状态: {status} | 返回: {resp}"
        })
    else:
        count = await flag_manager.resubmit_all_unsubmitted()
        return web.json_response({
            "success": True,
            "count": count,
            "message": f"已完成重提 {count} 条未成功的 Flag！"
        })

async def handle_smart_parse(request):
    data = await request.json()
    raw_text = data.get("text", "")
    parsed = ConfigParser.parse_text(raw_text)
    return web.json_response(parsed)

async def handle_apply_parsed(request):
    data = await request.json()
    targets = data.get("targets", [])
    submitter_cfg = data.get("submitter", {})

    # Save targets
    target_path = os.path.join(BASE_DIR, "config", "targets.txt")
    with open(target_path, "w", encoding="utf-8") as f:
        f.write("# AWD 目标靶机 IPv4 列表 (智能导入)\n")
        for t in targets:
            f.write(f"{t}\n")

    # Save submitter
    if submitter_cfg:
        sub_path = os.path.join(BASE_DIR, "config", "submitter.json")
        with open(sub_path, "w", encoding="utf-8") as f:
            json.dump(submitter_cfg, f, indent=2, ensure_ascii=False)

    logger.info(f"Smart config applied: {len(targets)} targets, Submitter URL: {submitter_cfg.get('url')}")
    return web.json_response({"success": True, "message": f"成功应用 {len(targets)} 个靶机 IP 及提交配置！"})

async def handle_toggle_scheduler(request):
    new_state = not scheduler.enabled
    scheduler.toggle_scheduler(new_state)
    return web.json_response({"success": True, "scheduler_enabled": new_state})

async def handle_toggle_watcher(request):
    new_state = not scheduler.watcher_enabled
    scheduler.toggle_watcher(new_state)
    return web.json_response({"success": True, "watcher_enabled": new_state})

async def handle_toggle_auto_trigger(request):
    new_state = not scheduler.auto_trigger_on_new_poc
    scheduler.toggle_auto_trigger(new_state)
    status_str = "已开启" if new_state else "已禁用"
    return web.json_response({
        "success": True,
        "auto_trigger_on_new_poc": new_state,
        "message": f"新增 PoC 自动打一轮: {status_str}"
    })

async def handle_start_interval(request):
    """Starts the 10-minute recurring schedule immediately from Round 1."""
    scheduler.reset_interval_start()
    asyncio.create_task(scheduler.run_round(1))
    return web.json_response({
        "success": True,
        "message": "已成功启动 10 分钟自动轮训！已立即触发第 1 轮调度，后续每 10 分钟自动执行下一轮。"
    })

async def handle_toggle_schedule_mode(request):
    """Toggles between 'interval' (10-min recurring) and 'clock' (13:30 start)."""
    new_mode = "clock" if scheduler.schedule_mode == "interval" else "interval"
    scheduler.schedule_mode = new_mode
    Database.set_setting("schedule_mode", new_mode)
    if new_mode == "interval":
        scheduler.reset_interval_start()
    mode_desc = "10分钟自动间隔循环" if new_mode == "interval" else "绝对时间定时 (13:30)"
    return web.json_response({
        "success": True,
        "schedule_mode": new_mode,
        "message": f"调度模式已切换为: {mode_desc}"
    })

async def handle_trigger_round(request):
    if scheduler.is_executing_round:
        return web.json_response({"success": False, "message": "当前已有轮次正在并发执行中，请勿重复触发！"}, status=409)
    settings = scheduler.load_settings()
    curr_round, _, _ = scheduler.calculate_round(settings)
    target_round = curr_round if curr_round > 0 else 1
    asyncio.create_task(scheduler.run_round(target_round))
    return web.json_response({"success": True, "message": f"已触发执行第 {target_round} 轮任务"})

async def handle_test_get_flag(request):
    try:
        data = await request.json()
    except Exception:
        data = {}
    cmd = data.get("cmd", "").strip()
    if not cmd:
        curr_settings = scheduler.load_settings()
        cmd = curr_settings.get("get_flag_cmd", "").strip()
    if not cmd:
        return web.json_response({"success": False, "error": "未配置获取Flag命令"}, status=400)

    start_t = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=3.5)
            stdout_str = stdout_b.decode("utf-8", errors="replace")
            stderr_str = stderr_b.decode("utf-8", errors="replace")
            exit_code = proc.returncode
        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            return web.json_response({
                "success": False,
                "error": "执行超时 (3.5秒超时保护)",
                "duration_ms": int((time.perf_counter() - start_t) * 1000)
            })

        duration_ms = int((time.perf_counter() - start_t) * 1000)
        output_combined = stdout_str if stdout_str else stderr_str
        found_flags = flag_manager.extract_flags(output_combined)

        return web.json_response({
            "success": exit_code == 0,
            "exit_code": exit_code,
            "output": output_combined[:3000],
            "flags_found": found_flags,
            "duration_ms": duration_ms
        })
    except Exception as e:
        return web.json_response({
            "success": False,
            "error": str(e),
            "duration_ms": int((time.perf_counter() - start_t) * 1000)
        })

# ==================== Cron Task APIs ====================
async def handle_cron_status(request):
    """Returns cron status, remaining time, scripts, and recent execution history."""
    return web.json_response(cron_manager.get_status())

async def handle_cron_trigger(request):
    """Manually triggers execution of all cron tasks immediately."""
    asyncio.create_task(cron_manager.run_once())
    return web.json_response({"success": True, "message": "已触发后台自动任务立即运行"})

async def handle_cron_toggle(request):
    """Enables or disables periodic cron task execution."""
    data = await request.json()
    enable = data.get("enable", True)
    cron_manager.enabled = bool(enable)
    Database.set_setting("cron_enabled", cron_manager.enabled)
    logger.info(f"Cron auto-runner toggled: {cron_manager.enabled}")
    return web.json_response({"success": True, "enabled": cron_manager.enabled})

async def handle_logs(request):
    log_content = ""
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                log_content = "".join(lines[-200:])  # Last 200 lines
        except Exception as e:
            log_content = f"Error reading logs: {e}"
    return web.json_response({"logs": log_content})

# Background scheduler startup hook
async def on_startup(app):
    app["scheduler_task"] = asyncio.create_task(scheduler.start())
    app["cron_task"] = asyncio.create_task(cron_manager.start())

async def on_cleanup(app):
    scheduler.is_running = False
    cron_manager.is_running = False
    if "scheduler_task" in app:
        app["scheduler_task"].cancel()
    if "cron_task" in app:
        app["cron_task"].cancel()

def make_app():
    app = web.Application()
    app.router.add_get("/", handle_index)
    app.router.add_static("/static/", os.path.join(BASE_DIR, "web"))
    app.router.add_get("/style.css", lambda r: web.FileResponse(os.path.join(BASE_DIR, "web", "style.css")))
    app.router.add_get("/app.js", lambda r: web.FileResponse(os.path.join(BASE_DIR, "web", "app.js")))

    # APIs
    app.router.add_get("/api/status", handle_status)
    app.router.add_get("/api/flags", handle_flags)
    app.router.add_post("/api/flags/clear", handle_flags_clear)
    app.router.add_get("/api/tasks", handle_tasks)
    app.router.add_get("/api/pocs", handle_pocs)
    app.router.add_post("/api/pocs/sync", handle_pocs_sync)
    app.router.add_post("/api/pocs/toggle", handle_pocs_toggle)
    app.router.add_post("/api/pocs/delete", handle_pocs_delete)
    app.router.add_post("/api/pocs/clear", handle_pocs_clear)
    app.router.add_get("/api/vulns", handle_get_vulns)
    app.router.add_post("/api/vulns", handle_save_vulns)
    app.router.add_post("/api/vulns/clear", handle_clear_vulns)
    app.router.add_get("/api/settings", handle_get_settings)
    app.router.add_post("/api/settings", handle_save_settings)
    app.router.add_get("/api/targets", handle_get_targets)
    app.router.add_post("/api/targets", handle_save_targets)
    app.router.add_post("/api/targets/expand", handle_expand_targets)
    app.router.add_post("/api/targets/clear", handle_clear_targets)
    app.router.add_get("/api/submitter", handle_get_submitter)
    app.router.add_post("/api/submitter", handle_save_submitter)
    app.router.add_post("/api/submitter/parse_raw", handle_parse_submitter_raw)
    app.router.add_post("/api/submitter/import_raw", handle_import_submitter_raw)
    app.router.add_post("/api/submitter/test", handle_test_submitter)
    app.router.add_post("/api/flags/resubmit", handle_resubmit_flags)
    app.router.add_post("/api/smart_parse", handle_smart_parse)
    app.router.add_post("/api/apply_parsed", handle_apply_parsed)
    app.router.add_post("/api/toggle_scheduler", handle_toggle_scheduler)
    app.router.add_post("/api/toggle_watcher", handle_toggle_watcher)
    app.router.add_post("/api/toggle_auto_trigger", handle_toggle_auto_trigger)
    app.router.add_post("/api/trigger_round", handle_trigger_round)
    app.router.add_post("/api/scheduler/start_interval", handle_start_interval)
    app.router.add_post("/api/scheduler/toggle_mode", handle_toggle_schedule_mode)
    app.router.add_post("/api/test_get_flag", handle_test_get_flag)
    app.router.add_get("/api/logs", handle_logs)
    app.router.add_get("/api/cron/status", handle_cron_status)
    app.router.add_post("/api/cron/trigger", handle_cron_trigger)
    app.router.add_post("/api/cron/toggle", handle_cron_toggle)

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app

def main():
    parser = argparse.ArgumentParser(description="AWD-Red Automation Platform")
    parser.add_argument("--port", type=int, default=int(init_settings.get("web_port", 8800)), help="Web UI port")
    parser.add_argument("--host", default=init_settings.get("web_host", "0.0.0.0"), help="Web UI host")
    args = parser.parse_args()

    app = make_app()
    logger.info("==================================================")
    logger.info("⚔️  AWD-Red Automation Platform V1.0 Starting")
    logger.info(f"👉 Web Dashboard: http://localhost:{args.port}")
    logger.info(f"👉 PoC Incoming:  {os.path.join(BASE_DIR, 'pocs', 'incoming')}")
    logger.info("==================================================")
    web.run_app(app, host=args.host, port=args.port, print=None)

if __name__ == "__main__":
    main()
