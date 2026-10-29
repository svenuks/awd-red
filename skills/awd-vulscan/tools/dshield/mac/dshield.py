#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Native macOS command-line scanner compatible with D盾 rule data.

This is not the original D盾 Windows engine.  The original program is a
32-bit Windows PE application whose scanner lives in Windows DLLs.  This
tool provides a native macOS CLI that reads the local D盾 signature database,
adds source-flow heuristics, and emits D盾-style ``>|level|file|type`` lines.

The scanner only uses the Python standard library and is intended for
authorized source-code review and incident response work.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import fnmatch
import hashlib
import json
import os
import re
import struct
import sys
import time
import zlib
from pathlib import Path
from typing import Iterable, Iterator, Optional, Sequence


APP_NAME = "dshield-mac"
VERSION = "0.1.0"

DEFAULT_EXTENSIONS = {
    ".php",
    ".php3",
    ".php4",
    ".php5",
    ".php7",
    ".php8",
    ".phtml",
    ".phar",
    ".inc",
    ".asp",
    ".asa",
    ".aspx",
    ".ashx",
    ".asmx",
    ".jsp",
    ".jspx",
    ".js",
    ".html",
    ".htm",
    ".tpl",
}

SERVER_SCRIPT_EXTENSIONS = {
    ".php",
    ".php3",
    ".php4",
    ".php5",
    ".php7",
    ".php8",
    ".phtml",
    ".phar",
    ".inc",
    ".asp",
    ".asa",
    ".aspx",
    ".ashx",
    ".asmx",
    ".jsp",
    ".jspx",
}

DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "__pycache__",
    "node_modules",
    ".DS_Store",
}

ZLIB_HEADERS = (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda")
COUNTED_RECORD_MARKER = b"\xdd\x00\x00\x00"

DANGEROUS_TOKEN_RE = re.compile(
    r"(?i)(?:"
    r"eval|assert|create_function|system|shell_exec|passthru|proc_open|"
    r"popen|pcntl_exec|base64_decode|gzinflate|gzuncompress|str_rot13|"
    r"file_put_contents|move_uploaded_file|fsockopen|curl_exec|preg_replace|"
    r"call_user_func|include|require"
    r")"
)

DECODER_RE = re.compile(
    r"(?i)\b(?:"
    r"base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|"
    r"hex2bin|pack|chr|urldecode|rawurldecode|openssl_decrypt|"
    r"convert_uuencode|convert_uudecode"
    r")\s*\("
)

REQUEST_SOURCE_RE = re.compile(
    r"""(?ix)
    \$_(?:GET|POST|REQUEST|COOKIE|FILES)\b
    |\$HTTP_(?:GET|POST|COOKIE|RAW_POST)_VARS\b
    |\$HTTP_RAW_POST_DATA\b
    |php://input
    |getallheaders\s*\(
    |apache_request_headers\s*\(
    |Request\s*(?:\.|\[|\()\s*(?:Form|QueryString|Params|Cookies|Item)?
    |request\.getParameter\w*\s*\(
    |getParameter\s*\(
    |\$_SERVER\s*\[\s*["']HTTP_
    |\$_SERVER\s*\[\s*["'](?:QUERY_STRING|REQUEST_URI)["']
    """
)

ASSIGN_RE = re.compile(
    r"(?P<var>\$[A-Za-z_]\w*)\s*(?<![=!<>])=(?!=)\s*(?P<expr>[^;]{0,1200});",
    re.S,
)

FOREACH_REQUEST_RE = re.compile(
    r"\bforeach\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b[^)]*?"
    r"\bas\s+(\$[A-Za-z_]\w*)",
    re.I | re.S,
)

FUNCTION_HEADER_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*\{",
    re.I,
)

COMMAND_SINKS = {
    "system",
    "shell_exec",
    "passthru",
    "exec",
    "popen",
    "proc_open",
    "pcntl_exec",
}

CODE_SINKS = {"eval", "assert", "create_function"}

FILE_WRITE_SINKS = {
    "file_put_contents",
    "fwrite",
    "fputs",
    "fopen",
    "move_uploaded_file",
}

INCLUDE_SINKS = {"include", "include_once", "require", "require_once"}

ALL_SINKS = (
    COMMAND_SINKS
    | CODE_SINKS
    | FILE_WRITE_SINKS
    | INCLUDE_SINKS
    | {
        "preg_replace",
        "call_user_func",
        "call_user_func_array",
        "unserialize",
        "extract",
        "parse_str",
    }
)

KNOWN_MARKERS = (
    ("b374k", "已知 webshell：b374k"),
    ("php-reverse-shell", "已知 webshell：php-reverse-shell"),
    ("behinder", "已知 webshell 客户端：Behinder"),
    ("godzilla", "已知 webshell 客户端：Godzilla"),
    ("冰蝎", "已知 webshell 客户端：冰蝎"),
    ("哥斯拉", "已知 webshell 客户端：哥斯拉"),
    ("蚁剑", "已知 webshell 客户端：蚁剑"),
)

SUSPICIOUS_COMMAND_RE = re.compile(
    r"""(?ix)
    \b(?:whoami|id|uname|ifconfig|ipconfig|net\s+user|net\s+localgroup|
    tasklist|ps\s+aux|wget|curl|nc|ncat|bash|sh|zsh|cmd(?:\.exe)?|
    powershell|certutil|bitsadmin|chmod|chown|useradd|passwd|
    cat|type|ls|dir|pwd|rm|del|kill|shutdown|reboot)\b
    """
)


class RuleLoadError(RuntimeError):
    """Raised when the local D盾 signature database cannot be decoded."""


@dataclasses.dataclass(frozen=True)
class Signature:
    raw: str
    normalized: str


@dataclasses.dataclass
class RuleSet:
    path: Path
    compressed_size: int
    decompressed_size: int
    categories: list[str]
    signatures: list[str]
    active: list[Signature]
    warnings: list[str]

    def info(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "compressed_bytes": self.compressed_size,
            "decompressed_bytes": self.decompressed_size,
            "categories": len(self.categories),
            "signatures": len(self.signatures),
            "active_signatures": len(self.active),
            "sha256": sha256_file(self.path),
            "warnings": self.warnings,
        }


@dataclasses.dataclass
class Finding:
    file: str
    level: int
    kind: str
    evidence: list[str] = dataclasses.field(default_factory=list)
    signature: Optional[str] = None
    engine: str = "heuristic"

    def to_dict(self) -> dict[str, object]:
        return {
            "file": self.file,
            "level": self.level,
            "type": self.kind,
            "engine": self.engine,
            "evidence": self.evidence,
            "signature": self.signature,
        }


@dataclasses.dataclass
class FunctionDef:
    name: str
    params: list[str]
    body: str
    header_start: int
    body_start: int
    body_end: int


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def truncate(text: str, limit: int = 180) -> str:
    text = text.replace("\r", " ").replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def decode_text(data: bytes) -> str:
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig", errors="replace")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    for encoding in ("utf-8", "gb18030", "gbk", "cp936"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def decode_rule_line(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8")
        if "\ufffd" not in text:
            return text
    except UnicodeDecodeError:
        pass
    try:
        return raw.decode("gb18030")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace")


def decompress_rule_database(data: bytes) -> bytes:
    """Return the decompressed body of a D盾 .dat/.db container."""

    if data.startswith(b"SQLite format 3\x00"):
        return data

    candidates: list[int] = []
    if data[:2] in ZLIB_HEADERS:
        candidates.append(0)
    for offset in range(0, min(4096, max(0, len(data) - 2))):
        if data[offset : offset + 2] in ZLIB_HEADERS:
            candidates.append(offset)

    for offset in dict.fromkeys(candidates):
        try:
            body = zlib.decompress(data[offset:])
        except zlib.error:
            continue
        if body:
            return body

    if data.startswith(b"\x1f\x8b"):
        import gzip

        try:
            return gzip.decompress(data)
        except OSError as exc:
            raise RuleLoadError(f"gzip 解压失败：{exc}") from exc

    raise RuleLoadError("没有找到可解压的 D盾 规则数据")


def parse_counted_records(body: bytes) -> list[list[str]]:
    """Extract CRLF-delimited text tables from a decompressed D盾 database."""

    records: list[list[str]] = []
    offset = 0
    while True:
        marker = body.find(COUNTED_RECORD_MARKER, offset)
        if marker < 0:
            break
        offset = marker + 1
        if marker + 8 > len(body):
            continue
        count = struct.unpack_from("<I", body, marker + 4)[0]
        if not 0 < count < 250_000:
            continue

        cursor = marker + 8
        lines: list[str] = []
        ok = True
        for _ in range(count):
            end = body.find(b"\r\n", cursor)
            if end < 0:
                ok = False
                break
            lines.append(decode_rule_line(body[cursor:end]))
            cursor = end + 2
        if ok and cursor < len(body) and body[cursor] == 0:
            records.append(lines)
            offset = cursor + 1

    return records


def strip_comments_and_strings(code: str) -> str:
    """Remove comments and replace string bodies with ``""``.

    The replacement keeps the code shape while removing identifiers and
    payload bytes that would otherwise create false signature matches.
    """

    output: list[str] = []
    index = 0
    length = len(code)
    while index < length:
        char = code[index]
        if char in ("'", '"'):
            quote = char
            output.append('""')
            index += 1
            while index < length:
                if code[index] == "\\":
                    index += 2
                    continue
                if code[index] == quote:
                    index += 1
                    break
                index += 1
            continue

        if char == "/" and index + 1 < length and code[index + 1] == "/":
            index += 2
            while index < length and code[index] not in "\r\n":
                index += 1
            continue

        if char == "#":
            index += 1
            while index < length and code[index] not in "\r\n":
                index += 1
            continue

        if char == "/" and index + 1 < length and code[index + 1] == "*":
            index += 2
            while index + 1 < length and not (code[index] == "*" and code[index + 1] == "/"):
                index += 1
            index += 2
            continue

        output.append(char)
        index += 1

    return "".join(output)


def normalize_code(code: str) -> str:
    """Approximate D盾's normalized code representation."""

    code = strip_comments_and_strings(code.lower())
    code = re.sub(r"\$[a-z_][a-z0-9_]*", "$v", code)
    code = re.sub(r"\b0x[0-9a-f]+\b|\b\d+(?:\.\d+)?\b", "", code)
    code = re.sub(r"\$v\s*\[[^\]]*\]", "$v[]", code)
    code = re.sub(r"\$v\s*\{[^}]*\}", "$v{}", code)
    code = re.sub(r"\s+", "", code)
    return code


def build_active_signatures(signatures: Sequence[str]) -> list[Signature]:
    """Keep long, code-like signatures that are useful for exact matching."""

    active: list[Signature] = []
    seen: set[str] = set()
    for raw in signatures:
        if "|" in raw:
            continue
        normalized = normalize_code(raw)
        if len(normalized) < 24 or normalized in seen:
            continue
        if not DANGEROUS_TOKEN_RE.search(normalized):
            continue
        if normalized.startswith(("if(!defined(", "array(", "list(", "for($v=")):
            continue
        # Avoid matching a file that only contains a long generic PHP boilerplate.
        if normalized.count("$v") > 40 and "eval" not in normalized and "assert" not in normalized:
            continue

        # D盾's database contains both concrete samples and generic call
        # patterns.  Generic patterns such as ``preg_replace_callback($p,
        # create_function(`` are common in legitimate template engines and
        # produce too much noise in a standalone scanner.  Keep them only
        # when they contain a request source, a quoted anchor, or a very long
        # code fragment.
        has_request_source = REQUEST_SOURCE_RE.search(raw) is not None
        quoted_anchor = re.search(r"""["'][^"']{4,}["']""", raw) is not None
        strong_marker = re.search(
            r"(?i)\b(?:eval|assert|system|shell_exec|passthru|exec|"
            r"file_put_contents|base64_decode|gzinflate|gzuncompress|str_rot13)\b",
            raw,
        ) is not None
        if not (has_request_source or quoted_anchor or strong_marker and len(normalized) >= 80):
            continue
        seen.add(normalized)
        active.append(Signature(raw=raw, normalized=normalized))

    active.sort(key=lambda item: len(item.normalized), reverse=True)
    return active


def load_ruleset(path: Path) -> RuleSet:
    if not path.is_file():
        raise RuleLoadError(f"规则库不存在：{path}")
    data = path.read_bytes()
    body = decompress_rule_database(data)
    records = parse_counted_records(body)

    categories: list[str] = []
    signatures: list[str] = []
    warnings: list[str] = []
    for record in records:
        if record and record[0] == "正常":
            categories = record
        if not signatures or len(record) > len(signatures):
            signatures = record

    if not signatures:
        raise RuleLoadError("规则库中没有找到文本特征记录")
    if not categories:
        warnings.append("规则库没有找到规则类别表")

    active = build_active_signatures(signatures)
    if not active:
        warnings.append("没有筛出可用于精确匹配的特征，仍会使用启发式检测")

    return RuleSet(
        path=path.resolve(),
        compressed_size=len(data),
        decompressed_size=len(body),
        categories=categories,
        signatures=signatures,
        active=active,
        warnings=warnings,
    )


def default_db_path() -> Optional[Path]:
    env_path = os.environ.get("DSHIELD_DB")
    candidates: list[Path] = []
    if env_path:
        candidates.append(Path(env_path).expanduser())

    script_dir = Path(__file__).resolve().parent
    candidates.extend(
        [
            script_dir.parent / "Modules" / "ws_lib.db",
            Path.cwd() / "Modules" / "ws_lib.db",
            Path.cwd() / "ws_lib.db",
        ]
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None


def balanced_end(code: str, open_index: int, open_char: str, close_char: str) -> int:
    depth = 0
    index = open_index
    length = len(code)
    while index < length:
        char = code[index]
        if char in ("'", '"'):
            quote = char
            index += 1
            while index < length:
                if code[index] == "\\":
                    index += 2
                    continue
                if code[index] == quote:
                    index += 1
                    break
                index += 1
            continue
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return -1


def split_top_level(text: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char in ("'", '"'):
            quote = char
            index += 1
            while index < length:
                if text[index] == "\\":
                    index += 2
                    continue
                if text[index] == quote:
                    index += 1
                    break
                index += 1
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
        index += 1
    tail = text[start:].strip()
    if tail or parts:
        parts.append(tail)
    return parts


def iter_calls(
    code: str, names: Iterable[str]
) -> Iterator[tuple[str, str, int, int]]:
    name_pattern = "|".join(
        re.escape(name) for name in sorted(set(names), key=len, reverse=True)
    )
    if not name_pattern:
        return
    pattern = re.compile(
        r"(?<![\w$])(?P<name>" + name_pattern + r")\s*\(",
        re.I,
    )
    for match in pattern.finditer(code):
        open_index = match.end() - 1
        end = balanced_end(code, open_index, "(", ")")
        if end < 0:
            continue
        yield (
            match.group("name").lower(),
            code[open_index + 1 : end],
            match.start(),
            end,
        )


def expr_references_var(expr: str, variable: str) -> bool:
    return re.search(re.escape(variable) + r"(?!\w)", expr) is not None


def expr_has_request_input(expr: str, tainted: set[str]) -> bool:
    if REQUEST_SOURCE_RE.search(expr):
        return True
    return any(expr_references_var(expr, variable) for variable in tainted)


def derive_tainted(code: str, initial: Optional[set[str]] = None) -> set[str]:
    tainted = set(initial or ())
    for match in FOREACH_REQUEST_RE.finditer(code):
        tainted.add(match.group(1))

    for _ in range(6):
        changed = False
        for match in ASSIGN_RE.finditer(code):
            variable = match.group("var")
            if variable in tainted:
                continue
            expr = match.group("expr")
            if REQUEST_SOURCE_RE.search(expr) or any(
                expr_references_var(expr, item) for item in tainted
            ):
                tainted.add(variable)
                changed = True
        if not changed:
            break
    return tainted


def extract_functions(code: str) -> list[FunctionDef]:
    functions: list[FunctionDef] = []
    for match in FUNCTION_HEADER_RE.finditer(code):
        open_index = match.end() - 1
        end = balanced_end(code, open_index, "{", "}")
        if end < 0:
            continue
        params: list[str] = []
        for raw_param in split_top_level(match.group("params")):
            variable = re.search(r"\$([A-Za-z_]\w*)", raw_param)
            if variable:
                params.append("$" + variable.group(1))
        functions.append(
            FunctionDef(
                name=match.group("name"),
                params=params,
                body=code[open_index + 1 : end],
                header_start=match.start(),
                body_start=open_index + 1,
                body_end=end,
            )
        )
    return functions


def add_finding(findings: list[Finding], finding: Finding) -> None:
    key = (finding.file, finding.level, finding.kind)
    for existing in findings:
        if (existing.file, existing.level, existing.kind) == key:
            for evidence in finding.evidence:
                if evidence not in existing.evidence:
                    existing.evidence.append(evidence)
            if not existing.signature and finding.signature:
                existing.signature = finding.signature
            return
    findings.append(finding)


def analyze_sinks(
    code: str,
    tainted: set[str],
    rel_path: str,
    findings: list[Finding],
    context: str = "",
) -> None:
    for sink, expr, start, _end in iter_calls(code, ALL_SINKS):
        prefix = code[max(0, start - 2) : start]
        if sink in COMMAND_SINKS and (prefix.endswith("->") or prefix.endswith("::")):
            # PDO::exec(), $client->exec(), etc. are method calls, not the
            # PHP shell-execution primitive.
            continue
        is_tainted = expr_has_request_input(expr, tainted)
        has_decoder = DECODER_RE.search(expr) is not None
        literal = "$" not in expr

        level = 0
        kind = ""
        evidence: list[str] = []

        if sink in CODE_SINKS:
            if is_tainted:
                level = 5
                kind = f"请求参数进入 {sink}() 执行"
                evidence.append(f"{sink}() 的参数可追溯到请求输入")
            elif has_decoder:
                level = 5
                kind = f"{sink}() 执行编码/压缩载荷"
                evidence.append("调用链包含解码或解压函数")
            else:
                level = 2
                kind = f"动态代码执行 {sink}()"
                evidence.append("动态代码执行，未发现直接请求输入")

        elif sink in COMMAND_SINKS:
            if is_tainted:
                level = 5
                kind = f"请求参数进入 {sink}() 命令执行"
                evidence.append(f"{sink}() 的参数可追溯到请求输入")
            elif has_decoder:
                level = 4
                kind = f"{sink}() 执行编码命令"
                evidence.append("命令参数包含解码/解压调用")
            elif literal:
                level = 3
                kind = f"字面量命令执行 {sink}()"
                evidence.append(f"命令：{truncate(expr, 140)}")
                if SUSPICIOUS_COMMAND_RE.search(expr):
                    level = 4
                    evidence.append("命令包含敏感系统操作")
            else:
                level = 2
                kind = f"动态命令执行 {sink}()"
                evidence.append("命令由运行时变量构成")

        elif sink in INCLUDE_SINKS:
            if is_tainted:
                level = 4
                kind = "请求参数进入文件包含"
                evidence.append(f"{sink}() 的路径可追溯到请求输入")
            else:
                level = 0

        elif sink in FILE_WRITE_SINKS:
            args = split_top_level(expr)
            if sink == "fopen":
                mode = args[1] if len(args) > 1 else ""
                if not re.search(r"[waxc+]", mode, re.I):
                    level = 0
                    continue

            if is_tainted:
                executable_target = re.search(
                    r"(?i)\.(?:php\d?|phtml|asp|aspx|jsp|jspx)\b", expr
                ) is not None
                writes_code = re.search(
                    r"(?i)(?:<\?php|eval\s*\(|assert\s*\(|system\s*\()", expr
                ) is not None
                validated_upload = (
                    sink == "move_uploaded_file"
                    and re.search(
                        r"(?i)(?:getimagesize|exif_imagetype|finfo_open|"
                        r"mime_content_type|in_array\s*\(|getfileext\s*\(|"
                        r"pathinfo\s*\()",
                        code,
                    )
                    is not None
                )
                template_write = (
                    sink in {"fopen", "fwrite", "fputs"}
                    and re.search(
                        r"(?i)(?:is_writable|template|templates|editor)",
                        code,
                    )
                    is not None
                )
                if executable_target or writes_code:
                    level = 5
                    kind = "请求参数写入可执行脚本"
                    evidence.append(f"{sink}() 的目标或内容具有脚本执行特征")
                elif validated_upload or template_write:
                    level = 2
                    kind = "请求参数进入文件写入"
                    evidence.append("检测到上传/模板校验逻辑，降为人工复核")
                else:
                    level = 3
                    kind = "请求参数进入文件写入"
                    evidence.append(f"{sink}() 的参数可追溯到请求输入")
            elif has_decoder:
                level = 3
                kind = "编码数据写入文件"
                evidence.append("文件写入调用包含解码/解压函数")
            else:
                level = 0

        elif sink in {"call_user_func", "call_user_func_array"}:
            first_arg = split_top_level(expr)[0] if expr.strip() else ""
            if expr_has_request_input(first_arg, tainted):
                level = 5
                kind = "请求参数作为回调函数执行"
                evidence.append(f"{sink}() 的回调名来自请求输入")
            else:
                level = 0

        elif sink == "preg_replace":
            has_eval_modifier = re.search(r"/[a-z]*e[a-z]*[\"']", expr, re.I) is not None
            if has_eval_modifier:
                level = 5 if is_tainted else 4
                kind = "preg_replace /e 代码执行"
                evidence.append("preg_replace 使用 /e 修饰符")
            else:
                level = 0

        elif sink == "unserialize":
            if is_tainted:
                level = 4
                kind = "请求参数进入反序列化"
                evidence.append("unserialize() 的参数可追溯到请求输入")
            else:
                level = 0

        elif sink in {"extract", "parse_str"}:
            if is_tainted:
                level = 4
                kind = "请求参数批量注入变量"
                evidence.append(f"{sink}() 将请求数据展开为变量")
            else:
                level = 0

        if level <= 0 or level < 2:
            continue
        if context:
            evidence.append(context)
        add_finding(
            findings,
            Finding(
                file=rel_path,
                level=level,
                kind=kind,
                evidence=evidence,
                engine="heuristic",
            ),
        )


def analyze_dynamic_calls(
    code: str,
    tainted: set[str],
    rel_path: str,
    findings: list[Finding],
) -> None:
    direct_patterns = (
        r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]*\]\s*\(",
        r"\$\{[^}]+\}\s*\(",
    )
    for pattern in direct_patterns:
        if re.search(pattern, code, re.I):
            add_finding(
                findings,
                Finding(
                    file=rel_path,
                    level=5,
                    kind="动态函数调用",
                    evidence=["请求数据被直接当作函数名或函数表达式执行"],
                ),
            )
            break

    for match in re.finditer(r"(?<![\w$])(?P<var>\$[A-Za-z_]\w*)\s*\(", code):
        variable = match.group("var")
        if variable not in tainted:
            continue
        before = code[max(0, match.start() - 40) : match.start()]
        if re.search(r"\bfunction\s*$", before, re.I):
            continue
        add_finding(
            findings,
            Finding(
                file=rel_path,
                level=5,
                kind="变量函数调用",
                evidence=[f"{variable} 可追溯到请求输入，并被作为函数调用"],
            ),
        )


def analyze_wrappers(
    code: str,
    tainted: set[str],
    rel_path: str,
    findings: list[Finding],
) -> None:
    functions = extract_functions(code)
    if not functions:
        return

    for function in functions:
        for name, args_text, start, end in iter_calls(code, [function.name]):
            if function.header_start <= start <= function.body_end:
                continue
            if start >= function.body_start and end <= function.body_end:
                continue
            args = split_top_level(args_text)
            body_tainted: set[str] = set()
            for param, argument in zip(function.params, args):
                if expr_has_request_input(argument, tainted):
                    body_tainted.add(param)
            if not body_tainted:
                continue
            local_tainted = derive_tainted(function.body, body_tainted)
            analyze_sinks(
                function.body,
                local_tainted,
                rel_path,
                findings,
                context=f"请求参数经 {function.name}() 传入",
            )


def analyze_signatures(
    code: str,
    normalized_code: str,
    rel_path: str,
    rules: RuleSet,
    findings: list[Finding],
) -> None:
    del code
    hits: list[Signature] = []
    for signature in rules.active:
        if signature.normalized in normalized_code:
            hits.append(signature)
            if len(hits) >= 5:
                break
    if not hits:
        return

    best = hits[0]
    strong_re = re.compile(
        r"(?i)\b(?:eval|assert|system|shell_exec|passthru|exec|popen|"
        r"proc_open|pcntl_exec|base64_decode|gzinflate|gzuncompress|"
        r"str_rot13|file_put_contents)\b"
    )
    for hit in hits:
        if strong_re.search(hit.raw):
            best = hit
            break
    evidence = [f"匹配 D盾 规则片段：{truncate(best.raw, 200)}"]
    if len(hits) > 1:
        evidence.append(f"另有 {len(hits) - 1} 条同类特征命中")
    strong_code = strong_re.search(best.raw)
    add_finding(
        findings,
        Finding(
            file=rel_path,
            level=5 if strong_code else 3,
            kind="D盾特征命中",
            evidence=evidence,
            signature=truncate(best.raw, 240),
            engine="dshield-signature",
        ),
    )


def analyze_markers(text: str, rel_path: str, findings: list[Finding]) -> None:
    lower_text = text.lower()
    for marker, description in KNOWN_MARKERS:
        if marker.lower() in lower_text:
            add_finding(
                findings,
                Finding(
                    file=rel_path,
                    level=5,
                    kind="已知 webshell 标记",
                    evidence=[description],
                ),
            )


def suspicious_path_level(rel_path: str) -> int:
    normalized = rel_path.replace("\\", "/").lower()
    parts = set(normalized.split("/"))
    if parts & {
        "upload",
        "uploads",
        "uploadfiles",
        "images",
        "image",
        "avatar",
        "avatars",
        "attachment",
        "attachments",
        "cache",
        "temp",
        "tmp",
    }:
        return 1
    if re.search(r"\.(?:php\d?|phtml|asp|aspx|jsp)\.(?:jpg|jpeg|png|gif|txt|zip)$", normalized):
        return 2
    return 0


def adjust_findings_for_path(rel_path: str, findings: list[Finding]) -> None:
    bump = suspicious_path_level(rel_path)
    if not bump:
        return
    for finding in findings:
        if finding.level < 3:
            continue
        old_level = finding.level
        finding.level = min(5, finding.level + bump)
        if finding.level != old_level:
            finding.evidence.append("可执行脚本位于上传/缓存/图片类目录，风险等级上调")


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    merged: dict[tuple[str, int, str], Finding] = {}
    for finding in findings:
        key = (finding.file, finding.level, finding.kind)
        if key not in merged:
            merged[key] = finding
        else:
            for evidence in finding.evidence:
                if evidence not in merged[key].evidence:
                    merged[key].evidence.append(evidence)
            if not merged[key].signature and finding.signature:
                merged[key].signature = finding.signature
    return sorted(merged.values(), key=lambda item: (-item.level, item.kind))


def scan_text(
    rel_path: str,
    text: str,
    rules: Optional[RuleSet],
    enable_signatures: bool = True,
    enable_heuristics: bool = True,
) -> list[Finding]:
    findings: list[Finding] = []
    normalized_code = normalize_code(text)
    suffix = Path(rel_path).suffix.lower()
    server_code = suffix in SERVER_SCRIPT_EXTENSIONS or bool(
        re.search(r"<\?(?:php|=)|<%|<%@", text[:16_384], re.I)
    )

    if enable_signatures and rules is not None and rules.active:
        analyze_signatures(text, normalized_code, rel_path, rules, findings)

    if enable_heuristics and server_code:
        tainted = derive_tainted(text)
        analyze_sinks(text, tainted, rel_path, findings)
        analyze_wrappers(text, tainted, rel_path, findings)
        analyze_dynamic_calls(text, tainted, rel_path, findings)
        analyze_markers(text, rel_path, findings)
    elif enable_heuristics:
        analyze_markers(text, rel_path, findings)

    adjust_findings_for_path(rel_path, findings)
    return deduplicate_findings(findings)


def looks_binary(data: bytes) -> bool:
    if not data:
        return False
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return False
    sample = data[:4096]
    return sample.count(b"\x00") > max(8, len(sample) // 10)


def iter_files(
    roots: Sequence[Path],
    extensions: set[str],
    excludes: Sequence[str],
    max_size: int,
) -> Iterator[tuple[Path, Path]]:
    for root in roots:
        root = root.expanduser().resolve()
        if root.is_file():
            if root.suffix.lower() in extensions:
                yield root, root.parent
            continue
        if not root.is_dir():
            continue

        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [
                name
                for name in dirnames
                if name not in DEFAULT_EXCLUDED_DIRS
                and not any(
                    fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(
                        str(Path(dirpath, name).relative_to(root)), pattern
                    )
                    for pattern in excludes
                )
            ]
            for filename in filenames:
                path = Path(dirpath) / filename
                if path.is_symlink():
                    continue
                if path.suffix.lower() not in extensions:
                    continue
                rel = path.relative_to(root)
                if any(
                    fnmatch.fnmatch(filename, pattern)
                    or fnmatch.fnmatch(rel.as_posix(), pattern)
                    for pattern in excludes
                ):
                    continue
                try:
                    if path.stat().st_size > max_size:
                        continue
                except OSError:
                    continue
                yield path, root


def scan_file(
    path: Path,
    root: Path,
    rules: Optional[RuleSet],
    enable_signatures: bool,
    enable_heuristics: bool,
    max_size: int,
) -> list[Finding]:
    try:
        if path.stat().st_size > max_size:
            return []
        data = path.read_bytes()
    except OSError:
        return []
    if looks_binary(data):
        return []
    text = decode_text(data)
    try:
        rel_path = path.relative_to(root).as_posix()
    except ValueError:
        rel_path = path.as_posix()
    return scan_text(
        rel_path,
        text,
        rules,
        enable_signatures=enable_signatures,
        enable_heuristics=enable_heuristics,
    )


def format_finding(finding: Finding) -> str:
    lines = [f"[{finding.level}] {finding.file}", f"    类型：{finding.kind}"]
    if finding.signature:
        lines.append(f"    特征：{truncate(finding.signature, 200)}")
    for evidence in finding.evidence[:6]:
        lines.append(f"    证据：{truncate(evidence, 240)}")
    return "\n".join(lines)


def format_text_report(
    roots: Sequence[Path],
    findings: list[Finding],
    rules: Optional[RuleSet],
    files_scanned: int,
    elapsed: float,
    min_level: int,
) -> str:
    lines = [
        f"{APP_NAME} {VERSION}（原生 macOS 兼容扫描器）",
        "说明：本工具复用 D盾 本地特征并加入源码流向分析，不是原版 D盾 引擎。",
    ]
    if rules:
        lines.append(f"规则库：{rules.path}")
        lines.append(
            f"规则：{len(rules.signatures)} 条文本特征，启用 {len(rules.active)} 条精确特征，"
            f"{len(rules.categories)} 个类别"
        )
    else:
        lines.append("规则库：未加载，仅使用启发式分析")
    lines.append(f"扫描目标：{', '.join(str(root) for root in roots)}")
    lines.append(f"扫描文件：{files_scanned} 个，耗时 {elapsed:.2f}s")
    lines.append("")

    visible = [finding for finding in findings if finding.level >= min_level]
    if not visible:
        lines.append(f"未发现等级 >= {min_level} 的可疑结果。")
        return "\n".join(lines)

    for finding in visible:
        lines.append(format_finding(finding))
        lines.append("")

    counts: dict[int, int] = {}
    for finding in visible:
        counts[finding.level] = counts.get(finding.level, 0) + 1
    files = len({finding.file for finding in visible})
    summary = "，".join(f"等级 {level}: {counts[level]}" for level in sorted(counts, reverse=True))
    lines.append(f"汇总：{files} 个文件，{len(visible)} 条结果；{summary}")
    return "\n".join(lines)


def dshield_log_lines(findings: Sequence[Finding], min_level: int) -> list[str]:
    lines: list[str] = []
    for finding in sorted(findings, key=lambda item: (-item.level, item.file)):
        if finding.level < min_level:
            continue
        safe_path = finding.file.replace("|", "/")
        safe_kind = finding.kind.replace("|", "/")
        lines.append(f">|{finding.level}|{safe_path}|{safe_kind}")
    return lines


def command_rule_info(args: argparse.Namespace) -> int:
    path = Path(args.db).expanduser() if args.db else default_db_path()
    if path is None:
        print("没有找到规则库。请用 --db 指定 Modules/ws_lib.db。", file=sys.stderr)
        return 2
    try:
        rules = load_ruleset(path)
    except Exception as exc:
        print(f"规则库读取失败：{exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"scanner": APP_NAME, "version": VERSION, "rules": rules.info()}, ensure_ascii=False, indent=2))
        return 0

    print(f"{APP_NAME} 规则库")
    print(f"路径: {rules.path}")
    print(f"压缩大小: {rules.compressed_size} 字节")
    print(f"解压大小: {rules.decompressed_size} 字节")
    print(f"文本特征: {len(rules.signatures)} 条")
    print(f"精确特征: {len(rules.active)} 条")
    print(f"类别: {len(rules.categories)} 个")
    for warning in rules.warnings:
        print(f"警告: {warning}")
    if rules.categories:
        print("类别列表:")
        for index, category in enumerate(rules.categories):
            print(f"  {index:02d}  {category}")
    return 0


def command_scan(args: argparse.Namespace) -> int:
    roots = [Path(item).expanduser() for item in (args.paths or ["."])]
    roots = [root.resolve() for root in roots]
    missing = [root for root in roots if not root.exists()]
    if missing:
        for root in missing:
            print(f"路径不存在：{root}", file=sys.stderr)
        return 2

    db_path = Path(args.db).expanduser() if args.db else default_db_path()
    rules: Optional[RuleSet] = None
    if not args.no_signatures and db_path is not None:
        try:
            rules = load_ruleset(db_path)
        except Exception as exc:
            print(f"[!] 规则库加载失败，继续使用启发式分析：{exc}", file=sys.stderr)
    elif not args.no_signatures:
        print("[!] 没有找到 Modules/ws_lib.db；继续使用启发式分析。", file=sys.stderr)

    extensions = set(DEFAULT_EXTENSIONS)
    if args.script_only:
        extensions = set(SERVER_SCRIPT_EXTENSIONS)
    if args.ext:
        extensions = {
            item.strip().lower() if item.strip().startswith(".") else "." + item.strip().lower()
            for item in args.ext.split(",")
            if item.strip()
        }

    excludes = list(args.exclude)
    max_size = parse_size(args.max_size)
    started = time.monotonic()
    findings: list[Finding] = []
    files_scanned = 0
    futures: list[concurrent.futures.Future[list[Finding]]] = []

    workers = args.jobs if args.jobs > 0 else min(8, os.cpu_count() or 4)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for path, root in iter_files(roots, extensions, excludes, max_size):
            files_scanned += 1
            futures.append(
                executor.submit(
                    scan_file,
                    path,
                    root,
                    rules,
                    not args.no_signatures,
                    not args.no_heuristics,
                    max_size,
                )
            )
            if not args.quiet and files_scanned % 200 == 0:
                print(f"[*] 已提交 {files_scanned} 个文件 ...", file=sys.stderr)

        for future in concurrent.futures.as_completed(futures):
            try:
                findings.extend(future.result())
            except Exception as exc:
                if not args.quiet:
                    print(f"[!] 扫描任务失败：{exc}", file=sys.stderr)

    findings = deduplicate_findings(findings)
    findings.sort(key=lambda item: (-item.level, item.file, item.kind))
    elapsed = time.monotonic() - started
    visible = [finding for finding in findings if finding.level >= args.min_level]

    report = {
        "scanner": APP_NAME,
        "version": VERSION,
        "mode": "native-macos-compatible",
        "disclaimer": "复用 D盾 本地特征和启发式分析，不是原版 D盾 引擎。",
        "rules": rules.info() if rules else None,
        "scan": {
            "paths": [str(root) for root in roots],
            "files": files_scanned,
            "elapsed_seconds": round(elapsed, 4),
            "min_level": args.min_level,
        },
        "findings": [finding.to_dict() for finding in visible],
    }

    if args.output:
        output_path = Path(args.output).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    if args.log:
        log_path = Path(args.log).expanduser()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            "\n".join(dshield_log_lines(visible, args.min_level)) + ("\n" if visible else ""),
            encoding="utf-8",
        )

    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
    elif not args.quiet:
        print(
            format_text_report(
                roots,
                findings,
                rules,
                files_scanned,
                elapsed,
                args.min_level,
            )
        )

    if args.fail_on_level > 0:
        return 1 if any(finding.level >= args.fail_on_level for finding in findings) else 0
    return 0


def parse_size(raw: str) -> int:
    value = raw.strip().lower()
    units = {"k": 1024, "kb": 1024, "m": 1024**2, "mb": 1024**2, "g": 1024**3, "gb": 1024**3}
    match = re.fullmatch(r"(\d+)([kmg]b?)?", value)
    if not match:
        raise argparse.ArgumentTypeError(f"无效大小：{raw}")
    number = int(match.group(1))
    unit = match.group(2) or ""
    return number * units.get(unit, 1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dshield",
        description=(
            "原生 macOS 命令行 webshell 扫描器。读取 D盾 本地规则库，"
            "输出 D盾 风格日志；不是原版 Windows D盾 引擎。"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例：\n"
            "  dshield scan /var/www/html\n"
            "  dshield scan ./webroot --min-level 4 --log dshield.log\n"
            "  dshield scan ./webroot --format json --output report.json\n"
            "  dshield rule-info\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="扫描目录或文件")
    scan.add_argument("paths", nargs="*", help="要扫描的目录/文件，默认当前目录")
    scan.add_argument("--db", default=None, help="D盾 ws_lib.db 路径；默认自动查找")
    scan.add_argument("--min-level", type=int, choices=range(2, 6), default=4, help="最低输出等级，默认 4")
    scan.add_argument("--script-only", action="store_true", help="只扫描服务端脚本扩展名")
    scan.add_argument("--ext", default=None, help="逗号分隔的扩展名，例如 .php,.jsp,.aspx")
    scan.add_argument("--exclude", action="append", default=[], help="排除 glob，可重复")
    scan.add_argument("--max-size", default="8M", help="单文件最大大小，默认 8M")
    scan.add_argument("--jobs", type=int, default=0, help="并发线程数，默认自动")
    scan.add_argument("--no-signatures", action="store_true", help="不使用精确特征匹配")
    scan.add_argument("--no-heuristics", action="store_true", help="不使用启发式分析")
    scan.add_argument("--format", choices=("text", "json"), default="text", help="输出格式")
    scan.add_argument("--output", default=None, help="将 JSON 报告写入文件")
    scan.add_argument("--log", default=None, help="写入 D盾 风格的 >|level|file|type 日志")
    scan.add_argument("--fail-on-level", type=int, choices=range(0, 6), default=0, help="达到该等级时退出码为 1")
    scan.add_argument("--quiet", action="store_true", help="只输出 JSON 或日志，不打印文本报告")
    scan.set_defaults(func=command_scan)

    rule_info = sub.add_parser("rule-info", help="查看规则库信息")
    rule_info.add_argument("--db", default=None, help="D盾 ws_lib.db 路径")
    rule_info.add_argument("--json", action="store_true", help="JSON 输出")
    rule_info.set_defaults(func=command_rule_info)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("\n[!] 已中断。", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
