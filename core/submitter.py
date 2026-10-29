"""
Submitter: Competition platform submission adapter.
Handles HTTP authentication, format templating, and response parsing.
"""

import os
import json
import re
import logging
import aiohttp
from typing import Dict, Any, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUBMITTER_CONFIG_PATH = os.path.join(BASE_DIR, "config", "submitter.json")

logger = logging.getLogger("submitter")

class Submitter:
    def __init__(self, config_path: str = SUBMITTER_CONFIG_PATH):
        self.config_path = config_path

    def load_config(self) -> Dict[str, Any]:
        if not os.path.exists(self.config_path):
            return {"enabled": False}
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to read submitter config: {e}")
            return {"enabled": False}

    async def submit_flag(self, flag: str) -> (str, str):
        """
        Submits a single flag to the competition server.
        Returns: (status, response_summary)
        status: 'success', 'failed', 'duplicate', 'skipped'
        """
        cfg = self.load_config()
        if not cfg.get("enabled"):
            return "skipped", "Submitter disabled in config"

        url = cfg.get("url")
        if not url:
            return "failed", "No submission URL configured"

        method = cfg.get("method", "POST").upper()
        headers = cfg.get("headers", {})
        body_template = cfg.get("body_template", '{"flag": "{flag}"}')
        success_pattern = cfg.get("success_keyword", r'"code":\s*(?:"200"|200|"0"|0)|\"成功\"|success|\"ok\"')
        duplicate_pattern = cfg.get("duplicate_keyword", r'repeat|duplicate|already|重复|已提交')

        # Format body or query (support both full flag and raw_flag without flag{} prefix)
        raw_flag = flag
        if flag.startswith("flag{") and flag.endswith("}"):
            raw_flag = flag[5:-1]
        elif flag.startswith("FLAG{") and flag.endswith("}"):
            raw_flag = flag[5:-1]

        body_str = (
            body_template.replace("{flag}", flag)
            .replace("{FLAG}", flag)
            .replace("{raw_flag}", raw_flag)
            .replace("{RAW_FLAG}", raw_flag)
        )

        try:
            timeout = aiohttp.ClientTimeout(total=5.0)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                if method == "POST":
                    # Check if json or form
                    is_json = headers.get("Content-Type", "").lower() == "application/json" or cfg.get("format") == "json"
                    if is_json:
                        try:
                            payload = json.loads(body_str)
                            async with session.post(url, json=payload, headers=headers) as resp:
                                resp_text = await resp.text()
                        except json.JSONDecodeError:
                            async with session.post(url, data=body_str, headers=headers) as resp:
                                resp_text = await resp.text()
                    else:
                        async with session.post(url, data=body_str, headers=headers) as resp:
                            resp_text = await resp.text()
                elif method == "GET":
                    target_url = url.replace("{flag}", flag)
                    async with session.get(target_url, headers=headers) as resp:
                        resp_text = await resp.text()
                else:
                    return "failed", f"Unsupported HTTP method: {method}"

                # Parse response
                resp_clean = resp_text.strip()[:500]
                summary = resp_clean
                try:
                    parsed = json.loads(resp_clean)
                    msg = parsed.get("message") or parsed.get("msg") or parsed.get("info")
                    code = parsed.get("code")
                    if msg is not None:
                        summary = f"[{code}] {msg}" if code is not None else str(msg)
                except Exception:
                    pass

                if re.search(duplicate_pattern, resp_clean, re.IGNORECASE):
                    return "duplicate", summary
                elif re.search(success_pattern, resp_clean, re.IGNORECASE):
                    return "success", summary
                else:
                    return "failed", summary

        except Exception as e:
            logger.error(f"Error submitting flag '{flag}': {e}")
            return "failed", str(e)
