"""
Cron Task Manager: Periodic runner for automated background Python scripts (e.g., every 10 minutes).
Executes all .py scripts located in `cron_tasks/` directory asynchronously.
Outputs are parsed for flags and logged.
"""

import os
import sys
import time
import asyncio
import logging
from pathlib import Path
from typing import Dict, Any, List

from core.db import Database
from core.flag_manager import FlagManager

logger = logging.getLogger("cron_task")

BASE_DIR = Path(__file__).resolve().parent.parent
CRON_DIR = BASE_DIR / "cron_tasks"

class CronTaskManager:
    def __init__(self, flag_manager: FlagManager = None, interval_seconds: int = 600):
        self.flag_manager = flag_manager
        self.interval_seconds = interval_seconds  # Default 10 minutes (600s)
        self.is_running = False
        self.is_executing = False
        self.last_run_time = 0
        self.next_run_time = 0
        self.enabled = Database.get_setting("cron_enabled", True)
        self.history: List[Dict[str, Any]] = []

    def get_scripts(self) -> List[Path]:
        """Scans cron_tasks/ directory for executable .py scripts."""
        if not CRON_DIR.exists():
            CRON_DIR.mkdir(parents=True, exist_ok=True)
            return []
        scripts = sorted(list(CRON_DIR.glob("*.py")))
        return [s for s in scripts if not s.name.startswith("_") and not s.name.startswith(".")]

    async def execute_single_script(self, script_path: Path) -> Dict[str, Any]:
        """Executes one Python script, captures stdout/stderr, extracts flags."""
        script_name = script_path.name
        start_t = time.time()
        logger.info(f"🔄 [Cron Task] Running: {script_name}...")

        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                str(script_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(BASE_DIR)
            )
            # Timeout protection: 120s per task
            stdout_data, stderr_data = await asyncio.wait_for(proc.communicate(), timeout=120.0)
            stdout = stdout_data.decode("utf-8", errors="replace")
            stderr = stderr_data.decode("utf-8", errors="replace")
            exit_code = proc.returncode
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            stdout = ""
            stderr = "Execution timed out (120s limit)"
            exit_code = -1
        except Exception as e:
            stdout = ""
            stderr = f"Execution error: {e}"
            exit_code = -1

        duration = round(time.time() - start_t, 2)
        combined = f"{stdout}\n{stderr}"

        found_flags = []
        if self.flag_manager:
            try:
                found_flags = await self.flag_manager.process_task_output(
                    stdout=stdout,
                    stderr=stderr,
                    round_num=0,
                    poc_name=f"cron_{script_name}",
                    target_ip="127.0.0.1"
                )
            except Exception as e:
                logger.warning(f"Error parsing flags from cron task {script_name}: {e}")

        status = "success" if exit_code == 0 else "failed"
        logger.info(f"🏁 [Cron Task] {script_name} finished in {duration}s (exit {exit_code}). Flags captured: {len(found_flags)}")

        return {
            "script": script_name,
            "status": status,
            "exit_code": exit_code,
            "duration": duration,
            "flags_found": found_flags,
            "executed_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_t)),
            "output_preview": stdout[:500] if stdout else stderr[:500]
        }

    async def run_once(self) -> List[Dict[str, Any]]:
        """Executes all scripts in cron_tasks/ in parallel or batch."""
        scripts = self.get_scripts()
        if not scripts:
            logger.info("ℹ️ [Cron Task] No .py scripts found in cron_tasks/ directory.")
            return []

        self.is_executing = True
        logger.info(f"🚀 [Cron Task] Starting scheduled run: {len(scripts)} scripts found.")
        results = []
        try:
            tasks = [self.execute_single_script(s) for s in scripts]
            results = await asyncio.gather(*tasks, return_exceptions=False)
            self.last_run_time = time.time()
            self.history = (results + self.history)[:50] # Keep last 50
        except Exception as e:
            logger.error(f"Error during cron run: {e}")
        finally:
            self.is_executing = False

        return results

    async def start(self):
        """Main loop: runs every interval_seconds (default 10 minutes = 600s)."""
        self.is_running = True
        logger.info(f"⏰ [Cron Task Manager] Started. Interval: {self.interval_seconds}s (10 min). Directory: {CRON_DIR}")

        while self.is_running:
            try:
                now = time.time()
                self.next_run_time = now + self.interval_seconds

                if self.enabled:
                    await self.run_once()

                # Sleep in increments of 1 second so stopping/toggling is responsive
                for _ in range(self.interval_seconds):
                    if not self.is_running:
                        break
                    await asyncio.sleep(1)

            except Exception as e:
                logger.error(f"Cron loop exception: {e}")
                await asyncio.sleep(5)

    def get_status(self) -> Dict[str, Any]:
        """Status for web API."""
        now = time.time()
        remaining = max(0, int(self.next_run_time - now)) if self.next_run_time > 0 else 0
        scripts = [s.name for s in self.get_scripts()]
        return {
            "enabled": self.enabled,
            "interval_seconds": self.interval_seconds,
            "remaining_seconds": remaining,
            "is_executing": self.is_executing,
            "script_count": len(scripts),
            "scripts": scripts,
            "last_run_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.last_run_time)) if self.last_run_time else None,
            "recent_results": self.history[:10]
        }
