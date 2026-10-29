"""
Competition Config Parser: Automatically extracts targets, submission endpoints, and tokens from raw text.
Supports IP ranges (e.g. 192.168.1.1-255, 192.168.1.1-192.168.1.254) and CIDR (192.168.1.0/24).
Safe parsing without shell execution.
"""

import re
import ipaddress
from typing import Dict, Any, List

# Regex patterns
IPV4_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
IP_SUFFIX_RANGE_PATTERN = re.compile(r"\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)([0-9]{1,3})\s*-\s*([0-9]{1,3})\b")
IP_FULL_RANGE_PATTERN = re.compile(r"\b((?:[0-9]{1,3}\.){3}[0-9]{1,3})\s*-\s*((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b")
CIDR_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}\b")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
TOKEN_PATTERN = re.compile(r"(?:token|auth|key|secret|authorization)[:= \t]+([a-zA-Z0-9_\-\.]{8,128})", re.IGNORECASE)
BEARER_PATTERN = re.compile(r"Bearer\s+([a-zA-Z0-9_\-\.]{8,128})", re.IGNORECASE)

class ConfigParser:
    @staticmethod
    def expand_target_item(item: str) -> List[str]:
        """
        Expands a single target string which could be:
        - Suffix range: 192.168.1.1-255
        - Full range: 192.168.1.1-192.168.1.254
        - CIDR: 192.168.1.0/24
        - Single IPv4: 192.168.1.1
        """
        item = item.strip()
        if not item or item.startswith("#"):
            return []

        expanded = []

        # 1. CIDR notation (e.g., 192.168.1.0/24)
        if "/" in item:
            try:
                net = ipaddress.ip_network(item, strict=False)
                for ip in net.hosts():
                    expanded.append(str(ip))
                return expanded
            except ValueError:
                pass

        # 2. Suffix range (e.g., 192.168.1.1-255 or 192.168.1.1-100)
        m_suffix = IP_SUFFIX_RANGE_PATTERN.fullmatch(item)
        if m_suffix:
            prefix = m_suffix.group(1)
            start = int(m_suffix.group(2))
            end = int(m_suffix.group(3))
            if 0 <= start <= 255 and 0 <= end <= 255 and start <= end:
                for i in range(start, end + 1):
                    expanded.append(f"{prefix}{i}")
                return expanded

        # 3. Full IP range (e.g., 192.168.1.1-192.168.1.50)
        if "-" in item:
            parts = item.split("-", 1)
            ip_start_str = parts[0].strip()
            ip_end_str = parts[1].strip()

            # Handle case where second part is just integer: 192.168.1.1-255
            if ip_end_str.isdigit() and "." in ip_start_str:
                prefix = ip_start_str.rsplit(".", 1)[0] + "."
                start_val = int(ip_start_str.rsplit(".", 1)[1])
                end_val = int(ip_end_str)
                if 0 <= start_val <= 255 and 0 <= end_val <= 255 and start_val <= end_val:
                    for i in range(start_val, end_val + 1):
                        expanded.append(f"{prefix}{i}")
                    return expanded

            try:
                ip1 = ipaddress.IPv4Address(ip_start_str)
                ip2 = ipaddress.IPv4Address(ip_end_str)
                if int(ip1) <= int(ip2) and (int(ip2) - int(ip1) <= 2048):
                    for ip_int in range(int(ip1), int(ip2) + 1):
                        expanded.append(str(ipaddress.IPv4Address(ip_int)))
                    return expanded
            except ValueError:
                pass

        # 4. Single IPv4 Address
        try:
            ip = ipaddress.ip_address(item)
            if not ip.is_loopback and not ip.is_multicast:
                expanded.append(str(ip))
        except ValueError:
            pass

        return expanded

    @staticmethod
    def expand_all_targets(target_lines: List[str]) -> List[str]:
        """Expands and deduplicates a list of target expressions while preserving order."""
        result = []
        seen = set()
        for line in target_lines:
            for ip in ConfigParser.expand_target_item(line):
                if ip not in seen:
                    seen.add(ip)
                    result.append(ip)
        return result

    @staticmethod
    def parse_text(raw_text: str) -> Dict[str, Any]:
        """
        Parses unformatted competition instructions and extracts structured configuration.
        Supports single IPs, IP ranges (192.168.1.1-255), and CIDRs.
        """
        targets = []
        seen = set()

        def add_target(ip_str):
            if ip_str not in seen:
                seen.add(ip_str)
                targets.append(ip_str)

        # 1. First extract CIDR ranges
        for m in CIDR_PATTERN.finditer(raw_text):
            for ip in ConfigParser.expand_target_item(m.group(0)):
                add_target(ip)

        # 2. Extract suffix ranges like 192.168.1.1-255
        for m in IP_SUFFIX_RANGE_PATTERN.finditer(raw_text):
            for ip in ConfigParser.expand_target_item(m.group(0)):
                add_target(ip)

        # 3. Extract full IP ranges like 192.168.1.1-192.168.1.50
        for m in IP_FULL_RANGE_PATTERN.finditer(raw_text):
            for ip in ConfigParser.expand_target_item(m.group(0)):
                add_target(ip)

        # 4. Extract individual IPv4 addresses
        for m in IPV4_PATTERN.finditer(raw_text):
            ip_str = m.group(0)
            try:
                ip = ipaddress.ip_address(ip_str)
                if not ip.is_loopback and not ip.is_multicast:
                    add_target(ip_str)
            except ValueError:
                pass

        # 5. Extract URLs
        raw_urls = URL_PATTERN.findall(raw_text)
        submit_url = ""
        for u in raw_urls:
            if any(k in u.lower() for k in ["flag", "submit", "api", "score"]):
                submit_url = u
                break
        if not submit_url and raw_urls:
            submit_url = raw_urls[0]

        # 6. Detect HTTP Method
        method = "POST"
        if re.search(r"\b(curl\s+-X\s*GET|GET\s+http|method:\s*get)\b", raw_text, re.IGNORECASE):
            method = "GET"

        # 7. Extract Token / Auth header
        token = ""
        m_bearer = BEARER_PATTERN.search(raw_text)
        if m_bearer:
            token = m_bearer.group(1)
        else:
            m_token = TOKEN_PATTERN.search(raw_text)
            if m_token:
                token = m_token.group(1)

        # 8. Detect Flag parameter
        param_name = "flag"
        m_param = re.search(r"['\"]?([a-zA-Z0-9_]+)['\"]?\s*:\s*['\"]?\{flag\}", raw_text)
        if m_param:
            param_name = m_param.group(1)

        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        body_template = '{"' + param_name + '": "{flag}"}'
        if token:
            body_template = '{"' + param_name + '": "{flag}", "token": "' + token + '"}'

        return {
            "targets": targets,
            "target_count": len(targets),
            "submitter": {
                "enabled": bool(submit_url),
                "url": submit_url,
                "method": method,
                "format": "json",
                "headers": headers,
                "body_template": body_template,
                "token": token
            }
        }

    @staticmethod
    def clean_ps_value(val: str) -> str:
        """Cleans quotes and PowerShell escape sequences (`\" and `')."""
        val = val.strip()
        if val.startswith('"') and val.endswith('"') and len(val) >= 2:
            val = val[1:-1]
        elif val.startswith("'") and val.endswith("'") and len(val) >= 2:
            val = val[1:-1]
        return val.replace('`"', '"').replace("`'", "'")

    @staticmethod
    def parse_request_package(text: str) -> Dict[str, Any]:
        """
        Intelligently parses:
        1. PowerShell Invoke-WebRequest / Invoke-RestMethod (e.g. from Chrome DevTools 'Copy as PowerShell')
        2. cURL command (e.g. 'Copy as cURL')
        3. Raw HTTP Request (e.g. from Burp Suite)
        Extracts url, method, headers, and body template (auto-replacing flag with {raw_flag}).
        """
        text = text.strip()
        config = {
            "enabled": True,
            "url": "",
            "method": "POST",
            "format": "json",
            "headers": {},
            "body_template": '{"flag": "{raw_flag}"}',
            "success_keyword": r'"code":\s*(?:"00000"|"200"|200|"0"|0)|\"成功\"|success|40409|请勿重复作答',
            "duplicate_keyword": r"repeat|duplicate|already|重复|已提交|40409"
        }

        # Case 1: PowerShell Invoke-WebRequest / Invoke-RestMethod
        if "Invoke-WebRequest" in text or "Invoke-RestMethod" in text or "$session" in text:
            ua_m = re.search(r'\$session\.UserAgent\s*=\s*["\']([^"\']+)["\']', text)
            if ua_m:
                config["headers"]["User-Agent"] = ua_m.group(1)

            uri_m = re.search(r'-Uri\s+["\']?([^"\'\s`]+)["\']?', text)
            if uri_m:
                config["url"] = uri_m.group(1)

            method_m = re.search(r'-Method\s+["\']?([A-Za-z]+)["\']?', text)
            if method_m:
                config["method"] = method_m.group(1).upper()

            ct_m = re.search(r'-ContentType\s+["\']([^"\']+)["\']', text)
            if ct_m:
                config["headers"]["Content-Type"] = ct_m.group(1)

            headers_block = re.search(r'-Headers\s+@\{([\s\S]*?)\}', text)
            if headers_block:
                for line in headers_block.group(1).splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    eq_idx = line.find("=")
                    if eq_idx != -1:
                        raw_k = line[:eq_idx].strip().strip('"\'')
                        raw_v = ConfigParser.clean_ps_value(line[eq_idx+1:])
                        k_lower = raw_k.lower()
                        # Filter pseudo HTTP/2 headers or headers set automatically by requests/aiohttp
                        if k_lower in ["method", "path", "scheme", ":authority", ":method", ":path", ":scheme", "authority", "host", "content-length"]:
                            continue
                        config["headers"][raw_k] = raw_v

            body_m = re.search(r'-Body\s+["\']([\s\S]*?)["\']\s*$', text, re.MULTILINE)
            if not body_m:
                body_m = re.search(r'-Body\s+@["\']([\s\S]*?)["\']@', text)
            if not body_m:
                body_m = re.search(r'-Body\s+([^\r\n`]+)', text)

            if body_m:
                raw_body = ConfigParser.clean_ps_value(body_m.group(1))
                # Automatically substitute flag field values with {raw_flag}
                raw_body = re.sub(r'("flag"\s*:\s*)"[^"]*"', r'\1"{raw_flag}"', raw_body, flags=re.IGNORECASE)
                raw_body = re.sub(r'("flag"\s*:\s*)\'[^\']*\'', r'\1"{raw_flag}"', raw_body, flags=re.IGNORECASE)
                raw_body = re.sub(r'(flag=)[^&]+', r'\1{raw_flag}', raw_body, flags=re.IGNORECASE)
                config["body_template"] = raw_body

            return config

        # Case 2: cURL
        if text.startswith("curl") or " curl " in text:
            for part in re.findall(r'(https?://[^\s"\'\\]+)', text):
                config["url"] = part
                break

            method_m = re.search(r'-X\s+([A-Za-z]+)', text)
            if method_m:
                config["method"] = method_m.group(1).upper()

            for h in re.findall(r'-H\s+["\']([^"\']+)["\']', text):
                if ":" in h:
                    k, v = h.split(":", 1)
                    k = k.strip()
                    v = v.strip()
                    if k.lower() in ["host", "content-length"]:
                        continue
                    config["headers"][k] = v

            body_m = re.search(r'(?:--data-raw|--data|-d)\s+["\']([\s\S]*?)["\'](?:\s+-[A-Za-z]|$)', text)
            if body_m:
                raw_body = body_m.group(1)
                raw_body = re.sub(r'("flag"\s*:\s*)"[^"]*"', r'\1"{raw_flag}"', raw_body, flags=re.IGNORECASE)
                raw_body = re.sub(r'("flag"\s*:\s*)\'[^\']*\'', r'\1"{raw_flag}"', raw_body, flags=re.IGNORECASE)
                raw_body = re.sub(r'(flag=)[^&]+', r'\1{raw_flag}', raw_body, flags=re.IGNORECASE)
                config["body_template"] = raw_body

            return config

        # Case 3: Raw HTTP Request
        lines = text.splitlines()
        if lines:
            first_line = lines[0].strip()
            http_m = re.match(r'^(GET|POST|PUT|DELETE)\s+([^\s]+)\s+HTTP', first_line)
            if http_m:
                config["method"] = http_m.group(1)
                path = http_m.group(2)
                body_lines = []
                in_body = False
                host = ""

                for line in lines[1:]:
                    if not in_body:
                        if line.strip() == "":
                            in_body = True
                            continue
                        if ":" in line:
                            k, v = line.split(":", 1)
                            k = k.strip()
                            v = v.strip()
                            if k.lower() == "host":
                                host = v
                            elif k.lower() != "content-length":
                                config["headers"][k] = v
                    else:
                        body_lines.append(line)

                if host:
                    scheme = "https" if "443" in host or config.get("headers", {}).get("Origin", "").startswith("https") else "http"
                    config["url"] = f"{scheme}://{host}{path}"
                else:
                    config["url"] = path

                if body_lines:
                    raw_body = "\n".join(body_lines).strip()
                    raw_body = re.sub(r'("flag"\s*:\s*)"[^"]*"', r'\1"{raw_flag}"', raw_body, flags=re.IGNORECASE)
                    raw_body = re.sub(r'("flag"\s*:\s*)\'[^\']*\'', r'\1"{raw_flag}"', raw_body, flags=re.IGNORECASE)
                    raw_body = re.sub(r'(flag=)[^&]+', r'\1{raw_flag}', raw_body, flags=re.IGNORECASE)
                    config["body_template"] = raw_body

                return config

        # Fallback to ConfigParser.parse_text
        fallback = ConfigParser.parse_text(text).get("submitter", {})
        config.update({k: v for k, v in fallback.items() if v})
        return config
