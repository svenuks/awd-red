"""
Task Manager: Asynchronous process isolation, concurrency limiter, and timeout watchdog.
"""

import os
import sys
import time
import uuid
import asyncio
import logging
from typing import Dict, Any, List
from core.db import Database
from core.flag_manager import FlagManager

logger = logging.getLogger("task_manager")

class TaskManager:
    def __init__(self, flag_manager: FlagManager, poc_concurrency: int = 64, global_concurrency: int = 128, timeout_sec: float = 3.0):
        self.flag_manager = flag_manager
        self.poc_concurrency = poc_concurrency
        self.global_concurrency = global_concurrency
        self.timeout_sec = timeout_sec
        self.global_sem = asyncio.Semaphore(global_concurrency)
        self.active_tasks_count = 0

    async def execute_single_poc(self, round_num: int, poc: Dict[str, Any], target_ip: str, poc_sem: asyncio.Semaphore, get_flag_cmd: str = "") -> Dict[str, Any]:
        task_id = str(uuid.uuid4())[:12]
        poc_name = poc["name"]
        filepath = poc["filepath"]

        async with self.global_sem:
            async with poc_sem:
                self.active_tasks_count += 1
                start_time = time.perf_counter()
                status = "running"
                stdout_str = ""
                stderr_str = ""
                exit_code = None
                captured_flags = []

                try:
                    # Construct command with target_ip and get_flag_cmd
                    cmd = [sys.executable, filepath, target_ip] if filepath.endswith(".py") else [filepath, target_ip]
                    if get_flag_cmd:
                        cmd.append(get_flag_cmd)

                    # Inject environment variable for robust access
                    env = os.environ.copy()
                    if get_flag_cmd:
                        env["GET_FLAG_CMD"] = get_flag_cmd
                        env["AWD_GET_FLAG_CMD"] = get_flag_cmd

                    # Spawn isolated subprocess
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        env=env
                    )

                    try:
                        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_sec)
                        stdout_str = stdout_bytes.decode("utf-8", errors="replace")
                        stderr_str = stderr_bytes.decode("utf-8", errors="replace")
                        exit_code = proc.returncode
                        status = "success" if exit_code == 0 else "failed"

                    except asyncio.TimeoutError:
                        status = "timeout"
                        stderr_str = f"Execution timed out after {self.timeout_sec} seconds."
                        try:
                            proc.kill()
                            await proc.wait()
                        except ProcessLookupError:
                            pass

                except Exception as e:
                    status = "failed"
                    stderr_str = f"Execution error: {str(e)}"

                finally:
                    duration_ms = int((time.perf_counter() - start_time) * 1000)
                    self.active_tasks_count -= 1

                # Flag extraction and deduplication
                if stdout_str or stderr_str:
                    captured_flags = await self.flag_manager.process_task_output(
                        stdout_str, stderr_str, round_num, poc_name, target_ip
                    )

                flag_captured_str = ",".join(captured_flags) if captured_flags else None

                if captured_flags:
                    logger.info(f"🎯 [HIT] R{round_num} | {poc_name} -> {target_ip} ({duration_ms}ms) | 成功捕获Flag: {flag_captured_str}")
                elif status == "success":
                    logger.info(f"✔ [OK] R{round_num} | {poc_name} -> {target_ip} ({duration_ms}ms) | 执行成功")
                elif status == "timeout":
                    logger.warning(f"⌛ [TIMEOUT] R{round_num} | {poc_name} -> {target_ip} (超过硬限制 {self.timeout_sec}s)")
                else:
                    logger.debug(f"✖ [FAIL] R{round_num} | {poc_name} -> {target_ip} ({duration_ms}ms) exit={exit_code}")

                # Persist task in database
                Database.record_task(
                    task_id=task_id,
                    round_num=round_num,
                    poc_name=poc_name,
                    target_ip=target_ip,
                    status=status,
                    exit_code=exit_code,
                    stdout=stdout_str[:1500],
                    stderr=stderr_str[:1500],
                    duration_ms=duration_ms,
                    flag_captured=flag_captured_str
                )

                return {
                    "id": task_id,
                    "round_num": round_num,
                    "poc_name": poc_name,
                    "target_ip": target_ip,
                    "status": status,
                    "flags": captured_flags,
                    "duration_ms": duration_ms
                }

    async def run_round_tasks(self, round_num: int, ready_pocs: List[Dict[str, Any]], targets: List[str], get_flag_cmd: str = "") -> Dict[str, Any]:
        """
        Launches all combinations of ready PoCs and target IPs in parallel.
        Ensures each PoC respects its concurrency limit.
        """
        if not ready_pocs or not targets:
            logger.warning(f"Round {round_num}: No ready PoCs ({len(ready_pocs)}) or targets ({len(targets)}) to run.")
            return {"total": 0, "success": 0, "flags": 0}

        tasks = []
        poc_semaphores = {p["name"]: asyncio.Semaphore(self.poc_concurrency) for p in ready_pocs}

        for poc in ready_pocs:
            sem = poc_semaphores[poc["name"]]
            for target_ip in targets:
                tasks.append(self.execute_single_poc(round_num, poc, target_ip, sem, get_flag_cmd=get_flag_cmd))

        logger.info(f"🚀 [Round {round_num}] Scheduled {len(tasks)} tasks across {len(ready_pocs)} PoCs and {len(targets)} targets.")
        results = await asyncio.gather(*tasks, return_exceptions=True)

        success_count = 0
        total_flags = 0
        for r in results:
            if isinstance(r, dict):
                if r.get("status") == "success":
                    success_count += 1
                total_flags += len(r.get("flags", []))

        return {
            "total": len(tasks),
            "success": success_count,
            "flags": total_flags
        }
