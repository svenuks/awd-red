"""
PoC Manager: Directory hot-reloading, syntax validation, registration, and lifecycle management.
"""

import os
import shutil
import hashlib
import py_compile
import logging
from typing import Dict, Any, List, Optional
from core.db import Database

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POCS_DIR = os.path.join(BASE_DIR, "pocs")
INCOMING_DIR = os.path.join(POCS_DIR, "incoming")
READY_DIR = os.path.join(POCS_DIR, "ready")
DISABLED_DIR = os.path.join(POCS_DIR, "disabled")
FAILED_DIR = os.path.join(POCS_DIR, "failed")

logger = logging.getLogger("poc_manager")

def compute_sha256(filepath: str) -> str:
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

class PoCManager:
    def __init__(self):
        for d in [INCOMING_DIR, READY_DIR, DISABLED_DIR, FAILED_DIR]:
            os.makedirs(d, exist_ok=True)
        self._mtime_cache: Dict[str, float] = {}
        self._incoming_mtime_cache: Dict[str, float] = {}
        self._incoming_retries: Dict[str, int] = {}

    def scan_and_sync(self) -> Dict[str, Any]:
        """
        Scans incoming, ready, and disabled folders.
        Processes newly delivered PoCs from AI in incoming/ with 1s hot-reload.
        Preserves files in incoming/ (copy2 instead of move) so manual test commands never fail.
        Synchronizes database state with filesystem using mtime caching.
        """
        actions = {"promoted": [], "updated": [], "failed": [], "synced": []}

        # 1. Process incoming directory (delivered by AI agent or user)
        if os.path.exists(INCOMING_DIR):
            for fname in os.listdir(INCOMING_DIR):
                if not fname.endswith((".py", ".sh")) or fname.startswith("."):
                    continue

                src_path = os.path.join(INCOMING_DIR, fname)
                poc_name = os.path.splitext(fname)[0]

                try:
                    src_mtime = os.path.getmtime(src_path)
                except OSError:
                    continue

                # Skip if already processed with identical mtime
                if self._incoming_mtime_cache.get(src_path) == src_mtime:
                    continue

                # Syntax validation
                valid, err = self.validate_poc(src_path)
                if not valid:
                    # Allow 1 cycle grace period (1s) in case file is still being flushed to disk
                    retries = self._incoming_retries.get(src_path, 0)
                    if retries < 1:
                        self._incoming_retries[src_path] = retries + 1
                        continue

                    self._incoming_retries.pop(src_path, None)
                    logger.error(f"[PoC Validation Error] {fname}: {err}")
                    dest_path = os.path.join(FAILED_DIR, fname)
                    shutil.copy2(src_path, dest_path)
                    f_hash = compute_sha256(dest_path)
                    self._incoming_mtime_cache[src_path] = src_mtime
                    Database.register_or_update_poc(poc_name, fname, dest_path, f_hash, status="failed")
                    actions["failed"].append({"name": poc_name, "error": err})
                    continue

                self._incoming_retries.pop(src_path, None)

                # Copy to ready/ (keep source in incoming/ so user test commands never fail!)
                dest_path = os.path.join(READY_DIR, fname)
                shutil.copy2(src_path, dest_path)
                os.chmod(dest_path, 0o755)
                f_hash = compute_sha256(dest_path)
                self._incoming_mtime_cache[src_path] = src_mtime
                self._mtime_cache[dest_path] = os.path.getmtime(dest_path)
                Database.register_or_update_poc(poc_name, fname, dest_path, f_hash, status="ready")
                actions["promoted"].append(poc_name)
                logger.info(f"[PoC Promoted] {fname} validated, active in ready/, and preserved in incoming/.")

        # 2. Sync ready directory (fast mtime check)
        if os.path.exists(READY_DIR):
            for fname in os.listdir(READY_DIR):
                if not fname.endswith((".py", ".sh")) or fname.startswith("."):
                    continue
                path = os.path.join(READY_DIR, fname)
                poc_name = os.path.splitext(fname)[0]
                try:
                    mtime = os.path.getmtime(path)
                except OSError:
                    continue
                if self._mtime_cache.get(path) == mtime:
                    actions["synced"].append(poc_name)
                    continue

                self._mtime_cache[path] = mtime
                f_hash = compute_sha256(path)
                if Database.register_or_update_poc(poc_name, fname, path, f_hash, status="ready"):
                    actions["updated"].append(poc_name)
                actions["synced"].append(poc_name)

        # 3. Sync disabled directory (fast mtime check)
        if os.path.exists(DISABLED_DIR):
            for fname in os.listdir(DISABLED_DIR):
                if not fname.endswith((".py", ".sh")) or fname.startswith("."):
                    continue
                path = os.path.join(DISABLED_DIR, fname)
                poc_name = os.path.splitext(fname)[0]
                try:
                    mtime = os.path.getmtime(path)
                except OSError:
                    continue
                if self._mtime_cache.get(path) == mtime:
                    continue

                self._mtime_cache[path] = mtime
                f_hash = compute_sha256(path)
                Database.register_or_update_poc(poc_name, fname, path, f_hash, status="disabled")

        return actions

    def validate_poc(self, filepath: str) -> (bool, Optional[str]):
        """Validates Python syntax and structure."""
        if filepath.endswith(".py"):
            try:
                py_compile.compile(filepath, doraise=True)
                return True, None
            except py_compile.PyCompileError as e:
                return False, str(e)
            except Exception as e:
                return False, str(e)
        return True, None

    def toggle_poc(self, poc_name: str, enable: bool) -> bool:
        """Enables (moves to ready/) or disables (moves to disabled/) a PoC."""
        # Find actual filename from DB if possible
        pocs = Database.get_all_pocs()
        target_poc = next((p for p in pocs if p["name"] == poc_name), None)
        fname = target_poc["filename"] if target_poc else f"{poc_name}.py"

        possible_names = [fname, f"{poc_name}.py", f"{poc_name}.sh"]

        if enable:
            for name in possible_names:
                src = os.path.join(DISABLED_DIR, name)
                dest = os.path.join(READY_DIR, name)
                if os.path.exists(src):
                    shutil.move(src, dest)
                    os.chmod(dest, 0o755)
                    f_hash = compute_sha256(dest)
                    Database.register_or_update_poc(poc_name, name, dest, f_hash, status="ready")
                    logger.info(f"PoC enabled: {poc_name} moved to ready/")
                    return True
                elif os.path.exists(dest):
                    # Already in ready directory
                    f_hash = compute_sha256(dest)
                    Database.register_or_update_poc(poc_name, name, dest, f_hash, status="ready")
                    return True
        else:
            for name in possible_names:
                src = os.path.join(READY_DIR, name)
                dest = os.path.join(DISABLED_DIR, name)
                if os.path.exists(src):
                    shutil.move(src, dest)
                    f_hash = compute_sha256(dest)
                    Database.register_or_update_poc(poc_name, name, dest, f_hash, status="disabled")
                    logger.info(f"PoC disabled: {poc_name} moved to disabled/")
                    return True
                elif os.path.exists(dest):
                    # Already in disabled directory
                    f_hash = compute_sha256(dest)
                    Database.register_or_update_poc(poc_name, name, dest, f_hash, status="disabled")
                    return True

        return False

    def clear_all_pocs(self) -> int:
        """Removes all PoC files from ready, incoming, disabled, failed and clears DB."""
        cleared_count = 0
        for d in [INCOMING_DIR, READY_DIR, DISABLED_DIR, FAILED_DIR]:
            if os.path.exists(d):
                for fname in os.listdir(d):
                    if fname.endswith((".py", ".sh")):
                        fpath = os.path.join(d, fname)
                        try:
                            os.remove(fpath)
                            cleared_count += 1
                        except Exception as e:
                            logger.error(f"Failed to remove {fpath}: {e}")

        Database.clear_all_pocs()
        logger.info(f"PoC Center: Cleared all {cleared_count} PoC files and reset DB records.")
        return cleared_count

    def delete_single_poc(self, poc_name: str) -> bool:
        """Deletes a single PoC by name from all folders and DB."""
        py_name = f"{poc_name}.py"
        sh_name = f"{poc_name}.sh"
        for d in [INCOMING_DIR, READY_DIR, DISABLED_DIR, FAILED_DIR]:
            for name in [py_name, sh_name]:
                fpath = os.path.join(d, name)
                if os.path.exists(fpath):
                    try:
                        os.remove(fpath)
                    except Exception as e:
                        logger.error(f"Failed to delete {fpath}: {e}")

        Database.delete_poc(poc_name)
        logger.info(f"PoC Center: Deleted PoC '{poc_name}' from disk and database.")
        return True
