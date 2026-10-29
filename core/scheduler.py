"""
Scheduler: Automated round calculation, round lifecycle management, and task triggering.
"""

import os
import json
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, List
from core.db import Database
from core.poc_manager import PoCManager
from core.task_manager import TaskManager
from core.flag_manager import FlagManager
from core.config_parser import ConfigParser

logger = logging.getLogger("scheduler")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETTINGS_PATH = os.path.join(BASE_DIR, "config", "settings.json")
TARGETS_PATH = os.path.join(BASE_DIR, "config", "targets.txt")

class Scheduler:
    def __init__(self, poc_manager: PoCManager, task_manager: TaskManager, flag_manager: FlagManager):
        self.poc_manager = poc_manager
        self.task_manager = task_manager
        self.flag_manager = flag_manager
        self.is_running = False
        self.last_executed_round = 0
        self.is_executing_round = False
        self.current_round = 0
        self.seconds_to_next_round = 0
        self.interval_start_time = None

        # Load persisted switches from DB if available
        self.enabled = Database.get_setting("scheduler_enabled", True)
        self.watcher_enabled = Database.get_setting("watcher_enabled", True)
        self.schedule_mode = Database.get_setting("schedule_mode", "interval") # "interval" or "clock"
        self.auto_trigger_on_new_poc = Database.get_setting("auto_trigger_on_new_poc", True)
        self._known_pocs = set()

    def load_settings(self) -> Dict[str, Any]:
        if not os.path.exists(SETTINGS_PATH):
            return {}
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to read settings: {e}")
            return {}

    def load_targets(self) -> List[str]:
        if not os.path.exists(TARGETS_PATH):
            return []
        raw_lines = []
        with open(TARGETS_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    raw_lines.append(line)
        return ConfigParser.expand_all_targets(raw_lines)

    def calculate_round(self, settings: Dict[str, Any]) -> (int, int, bool):
        """
        Returns: (current_round, seconds_to_next_round, is_competition_active)
        Supports:
        - "interval": Periodic execution every duration_sec starting from activation
        - "clock": Strict calendar start time
        """
        duration = int(settings.get("round_duration_sec", 600))
        mode = self.schedule_mode

        if mode == "interval":
            # If interval mode, start from interval_start_time (or current time if not set)
            if not self.interval_start_time:
                saved_start = Database.get_setting("interval_start_time")
                if saved_start:
                    try:
                        self.interval_start_time = datetime.strptime(saved_start, "%Y-%m-%d %H:%M:%S")
                    except Exception:
                        self.interval_start_time = datetime.now()
                else:
                    self.interval_start_time = datetime.now()
                    Database.set_setting("interval_start_time", self.interval_start_time.strftime("%Y-%m-%d %H:%M:%S"))

            diff_sec = (datetime.now() - self.interval_start_time).total_seconds()
            if diff_sec < 0:
                diff_sec = 0

            current_r = int(diff_sec // duration) + 1
            elapsed_in_round = int(diff_sec % duration)
            seconds_to_next = duration - elapsed_in_round
            return current_r, seconds_to_next, True

        else:
            # Clock mode: strictly adheres to competition_start_time
            start_time_str = settings.get("competition_start_time", "2026-10-23 13:30:00")
            try:
                start_dt = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                start_dt = datetime.now()

            diff_sec = (datetime.now() - start_dt).total_seconds()
            if diff_sec < 0:
                seconds_to_start = int(abs(diff_sec))
                return 0, seconds_to_start, False
            else:
                current_r = int(diff_sec // duration) + 1
                elapsed_in_round = int(diff_sec % duration)
                seconds_to_next = duration - elapsed_in_round
                return current_r, seconds_to_next, True

    def reset_interval_start(self):
        """Resets the interval timer to now, immediately beginning Round 1."""
        self.interval_start_time = datetime.now()
        Database.set_setting("interval_start_time", self.interval_start_time.strftime("%Y-%m-%d %H:%M:%S"))
        self.last_executed_round = 0
        self.schedule_mode = "interval"
        Database.set_setting("schedule_mode", "interval")
        self.enabled = True
        Database.set_setting("scheduler_enabled", True)
        logger.info("Interval scheduler reset: starting from now as Round 1.")

    def toggle_scheduler(self, enable: bool):
        self.enabled = enable
        Database.set_setting("scheduler_enabled", enable)
        logger.info(f"Scheduler state changed: enabled={enable}")

    def toggle_watcher(self, enable: bool):
        self.watcher_enabled = enable
        Database.set_setting("watcher_enabled", enable)
        logger.info(f"Watcher state changed: enabled={enable}")

    def toggle_auto_trigger(self, enable: bool):
        self.auto_trigger_on_new_poc = enable
        Database.set_setting("auto_trigger_on_new_poc", enable)
        logger.info(f"Auto-trigger on new PoC state changed: enabled={enable}")

    async def trigger_new_poc_round(self, new_pocs: List[str]):
        """
        Triggered when a new PoC is detected for the very first time.
        Waits for any in-flight execution to finish, then immediately executes an attack round across all targets.
        """
        # Wait up to 10s if another round is currently executing
        wait_cycles = 0
        while self.is_executing_round and wait_cycles < 20:
            await asyncio.sleep(0.5)
            wait_cycles += 1

        settings = self.load_settings()
        curr_round, _, _ = self.calculate_round(settings)
        target_round = curr_round if curr_round > 0 else 1

        logger.info(f"🚀 [New PoC Wave] 针对新增 PoC {new_pocs} 启动第 {target_round} 轮全目标实战打击...")
        await self.run_round(target_round, reason=f"新增 PoC 自动首轮打击: {new_pocs}")

    async def run_round(self, round_num: int, reason: str = ""):
        if self.is_executing_round:
            logger.warning(f"Round {round_num} skipped: another round is already executing.")
            return

        self.is_executing_round = True
        start_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        Database.record_round_start(round_num, start_time_str)

        try:
            ready_pocs = Database.get_ready_pocs()
            targets = self.load_targets()
            settings = self.load_settings()
            get_flag_cmd = settings.get("get_flag_cmd", "")
            reason_str = f" ({reason})" if reason else ""
            logger.info(f"⏰ [Round Trigger] Starting Round {round_num}{reason_str} | Targets: {len(targets)}, Ready PoCs: {len(ready_pocs)}")

            results = await self.task_manager.run_round_tasks(round_num, ready_pocs, targets, get_flag_cmd=get_flag_cmd)

            Database.update_round_stats(
                round_num=round_num,
                total_tasks=results.get("total", 0),
                success_tasks=results.get("success", 0),
                flags_found=results.get("flags", 0),
                status="completed"
            )
            self.last_executed_round = round_num
            logger.info(f"🏁 [Round {round_num} Finished] Total Tasks: {results.get('total')}, Success: {results.get('success')}, Flags: {results.get('flags')}")

        except Exception as e:
            logger.error(f"Error executing round {round_num}: {e}")
            Database.update_round_stats(round_num, 0, 0, 0, status="failed")
        finally:
            self.is_executing_round = False

    async def start(self):
        self.is_running = True
        logger.info("AWD-Red Scheduler and Hot-Reload Watcher started.")

        # Sync existing files on startup and record known ready PoCs
        self.poc_manager.scan_and_sync()
        self._known_pocs = {p["name"] for p in Database.get_ready_pocs()}
        logger.info(f"Initialized known ready PoCs ({len(self._known_pocs)}): {list(self._known_pocs)}")

        # Calculate initial round to avoid backfilling missed rounds
        settings = self.load_settings()
        init_round, _, active = self.calculate_round(settings)
        if active:
            # Set last executed round to current so we don't retroactively execute
            self.last_executed_round = init_round - 1
            logger.info(f"System started mid-competition. Initializing at Round {init_round}.")

        tick_count = 0
        while self.is_running:
            try:
                settings = self.load_settings()
                curr_round, seconds_to_next, is_active = self.calculate_round(settings)
                self.current_round = curr_round
                self.seconds_to_next_round = seconds_to_next

                # Hot reload watcher every 1 second (with optimized mtime cache)
                if self.watcher_enabled:
                    actions = self.poc_manager.scan_and_sync()

                    # Keep _known_pocs aligned if any poc was deleted or disabled
                    current_ready_names = {p["name"] for p in Database.get_ready_pocs()}
                    self._known_pocs = self._known_pocs.intersection(current_ready_names)

                    # Identify newly added or promoted PoCs
                    promoted = actions.get("promoted", [])
                    new_pocs = [p for p in promoted if p not in self._known_pocs]
                    if not new_pocs:
                        new_pocs = list(current_ready_names - self._known_pocs)

                    if new_pocs:
                        for p in new_pocs:
                            self._known_pocs.add(p)

                        auto_trigger = settings.get("auto_trigger_on_new_poc", self.auto_trigger_on_new_poc)
                        if auto_trigger:
                            logger.info(f"⚡ [Auto Trigger] 第一次检测到新增 PoC {new_pocs}，立即自动触发新一轮打击！")
                            asyncio.create_task(self.trigger_new_poc_round(new_pocs))

                # Round execution check every second
                if self.enabled and is_active and curr_round > self.last_executed_round and not self.is_executing_round:
                    logger.info(f"⏰ [Round Trigger] Starting Round {curr_round}...")
                    asyncio.create_task(self.run_round(curr_round))

                tick_count += 1
                await asyncio.sleep(1)

            except Exception as e:
                logger.error(f"Scheduler loop error: {e}")
                await asyncio.sleep(1)
