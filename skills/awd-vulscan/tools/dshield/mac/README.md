# D盾 macOS 原生命令行兼容版

这个目录里是一个可以在 macOS 命令行直接运行的 webshell 扫描器。它直接读取
D盾 目录中的 `Modules/ws_lib.db`，复用本地特征数据，并加入请求参数流向、
编码/解压链、动态函数调用、文件写入等启发式检测。

先说清楚：它**不是原版 D盾 引擎的移植**。原版 `D_Safe_Manage.exe` 是 32 位
Windows PE 程序，扫描逻辑位于 `web_safe.dll` / `d_manage.dll`，没有公开源码，
无法在 macOS 上直接链接或原样编译。这个工具的目标是提供一个原生命令行替代品，
而不是冒充原版检测结果。

## 环境

- macOS
- Python 3.10 或更高版本（标准库即可，不需要安装第三方包）

当前工作区已经带有 D盾 规则库：

```text
Modules/ws_lib.db
```

## 运行

在 D盾 目录下直接执行：

```bash
./dshield scan /path/to/webroot
```

默认只输出等级 4 及以上（高置信度）的结果。扫描当前目录并写 D盾 风格日志：

```bash
./dshield scan . --min-level 4 --log dshield_scan.log
```

如果要做更宽的人工排查，可以降到等级 3：

```bash
./dshield scan . --min-level 3
```

输出 JSON 报告：

```bash
./dshield scan /path/to/webroot --format json --output report.json
```

只扫描 PHP/ASP/JSP 等服务端脚本：

```bash
./dshield scan /path/to/webroot --script-only
```

查看规则库信息：

```bash
./dshield rule-info
```

接入现有的 SSH 拉取/扫描流程：

```bash
python awd_pipeline.py scan \
  --dshield-runner native \
  --host 192.168.1.101 --user ctf --password '***' \
  --remote-root /var/www/html

python dshield_remote_scan.py \
  --runner native \
  --host 192.168.1.101 --user ctf --password '***' \
  --remote-root /var/www/html
```

也可以把命令加入 PATH：

```bash
export PATH="$PWD:$PATH"
dshield scan /path/to/webroot
```

或者建立软链接：

```bash
sudo ln -sf "$PWD/dshield" /usr/local/bin/dshield
```

## D盾 风格日志

`--log` 会生成类似下面的行：

```text
>|5|controllers/home.php|请求参数进入 assert() 执行
>|5|public/admin/images/sub.php|请求参数进入 eval() 执行
>|4|controllers/b.php|字面量命令执行 system()
```

日志中的等级是本工具的严重度分级，不等同于原版 D盾 的界面等级。

## 检测逻辑

1. **D盾 本地特征匹配**：从 `ws_lib.db` 解压文本特征，筛出较长的代码片段，
   对源码做变量名/字符串/数字/空白归一化后匹配。
2. **请求流向分析**：追踪 `$_GET`、`$_POST`、`$_REQUEST`、`$_COOKIE`、
   `php://input`、ASP.NET `Request`、JSP `getParameter` 等输入进入
   `eval`、`assert`、`system`、`shell_exec`、文件写入、文件包含等危险位置。
3. **简单函数包装传播**：例如 `dog($_POST[x])` 调用
   `function dog($a){ assert($a); }` 时，能够把请求参数传播到 `assert()`。
4. **编码/解压链**：识别 `base64_decode`、`gzinflate`、`gzuncompress`、
   `str_rot13`、`strrev` 等进入代码执行或命令执行的情况。
5. **可疑位置加权**：上传目录、图片目录、缓存目录中的可执行脚本会被提高等级。

## 限制

- 不能保证与原版 D盾 的检出率和误报率一致，原版引擎的私有规则语义和
  白名单逻辑没有公开。
- 特征库是 2021 年版本的本地数据，新的 webshell 变种主要依赖启发式规则。
- 默认只输出等级 4 及以上；等级 3 可能包含“危险但不一定是 webshell”的
  模板/上传代码，适合人工复查。
- 建议把结果当作初筛，结合源码上下文人工确认；不要自动删除生产文件。
- 仅用于你有明确授权的源码、测试环境或应急响应目标。
