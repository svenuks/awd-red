"""
Flag Manager: Extracts, deduplicates, archives by round, and manages automated submissions.
"""

import re
import logging
import asyncio
from typing import Optional, List
from core.db import Database
from core.submitter import Submitter

logger = logging.getLogger("flag_manager")

DEFAULT_FLAG_REGEX = re.compile(r"flag\{[a-zA-Z0-9_\-]+\}", re.IGNORECASE)

class FlagManager:
    def __init__(self, submitter: Optional[Submitter] = None):
        self.submitter = submitter or Submitter()
        self.flag_regex = DEFAULT_FLAG_REGEX

    def set_pattern(self, pattern_str: str):
        try:
            self.flag_regex = re.compile(pattern_str, re.IGNORECASE)
        except Exception as e:
            logger.error(f"Invalid regex pattern '{pattern_str}': {e}")

    def extract_flags(self, text: str) -> List[str]:
        if not text:
            return []
        matches = self.flag_regex.findall(text)
        if matches:
            return list(set(matches))
        # 兼容靶机直接返回 32/36/40 位 Hash 文本的情况
        hash_matches = re.findall(r"\b[a-fA-F0-9]{32,40}\b", text)
        if hash_matches:
            return [f"flag{{{h}}}" for h in set(hash_matches)]
        return []

    async def process_task_output(self, stdout: str, stderr: str, round_num: int, poc_name: str, target_ip: str) -> List[str]:
        """
        Extracts flags from PoC execution output, deduplicates, saves, and submits new flags.
        """
        combined = f"{stdout}\n{stderr}"
        found_flags = self.extract_flags(combined)

        new_flags = []
        for f in found_flags:
            # Hash deduplication in SQLite
            is_new = Database.save_flag(f, round_num, poc_name, target_ip)
            if is_new:
                new_flags.append(f)
                logger.info(f"🚩 [NEW FLAG] Captured from {target_ip} by {poc_name}: {f}")
                # Submit asynchronously
                asyncio.create_task(self._submit_and_record(f))
            else:
                logger.debug(f"[DUPLICATE FLAG] Ignored: {f}")

        return found_flags

    async def _submit_and_record(self, flag: str):
        import hashlib
        flag_hash = hashlib.sha256(flag.strip().encode("utf-8")).hexdigest()
        status, resp = await self.submitter.submit_flag(flag)
        Database.update_flag_submit_status(flag_hash, status, resp)
        logger.info(f"📬 [SUBMISSION] Flag: {flag} -> Status: {status} (Response: {resp[:100]})")

    async def submit_all_pending(self):
        """Batch submits all flags that remain in 'pending' state."""
        pending = Database.get_pending_flags()
        for item in pending:
            await self._submit_and_record(item["flag_val"])

    async def resubmit_flag(self, flag_hash: str) -> (str, str):
        """Resubmits a specific flag by its hash."""
        from core.db import get_db_connection
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT flag_val FROM flags WHERE flag_hash = ?", (flag_hash,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return "failed", "Flag not found"
        flag = row["flag_val"]
        status, resp = await self.submitter.submit_flag(flag)
        Database.update_flag_submit_status(flag_hash, status, resp)
        logger.info(f"📬 [RE-SUBMISSION] Flag: {flag} -> Status: {status} (Response: {resp[:100]})")
        return status, resp

    async def resubmit_all_unsubmitted(self) -> int:
        """Resubmits all flags that are 'pending', 'skipped', or 'failed'."""
        from core.db import get_db_connection
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT flag_hash, flag_val FROM flags WHERE submit_status IN ('pending', 'skipped', 'failed')")
        rows = cursor.fetchall()
        conn.close()
        count = 0
        for r in rows:
            status, resp = await self.submitter.submit_flag(r["flag_val"])
            Database.update_flag_submit_status(r["flag_hash"], status, resp)
            logger.info(f"📬 [RE-SUBMISSION] Flag: {r['flag_val']} -> Status: {status} (Response: {resp[:100]})")
            count += 1
        return count

    def clear_all(self):
        """Clears all captured flags from database."""
        Database.clear_all_flags()
        logger.info("Flag Manager: Cleared all flag records.")
