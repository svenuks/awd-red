# AWD 资产收集参考

## 资产分类框架

### 按功能划分

| 分类 | 典型资产 | 检查重点 |
|---|---|---|
| Web 入口 | index.php, admin.php, api.php | 是否存在 eval/assert/RCE 漏洞 |
| 配置文件 | config.php, settings.php, .env | DB 凭证、API Keys 是否硬编码 |
| 数据库 | MySQL, PostgreSQL, SQLite | 后台表、弱口令、SQL 注入 |
| 缓存层 | Redis, Memcached | 会话文件、缓存注入 |
| 文件存储 | 上传目录、日志文件 | 后门文件、可写性 |
| 定时任务 | crontab, systemd timers | 是否被利用做持久化 |

### 按重要性划分

| 优先级 | 标准 | 示例 |
|---|---|---|
| critical | 直接影响 flag 或核心业务 | 入口点、Flag 服务、DB 后台 |
| high | 存在已知漏洞或高影响 | 可 RCE 的 PHP 文件、弱口令 DB |
| medium | 需要关注但不紧急 | 常规服务、缓存、日志 |
| low | 底层支撑设施 | crontab、SSH 密钥、备份文件 |

## 常见资产状态

| 状态 | 含义 | 行动 |
|---|---|---|
| running | 正常运行 | 持续监控 |
| vulnerable | 存在已知漏洞 | 优先修复或打穿 |
| suspicious | 疑似异常但未确认 | 手动验证 |
| clean | 无异常 | 保持观察 |
| gone | 已消失/被清理 | 记录变化 |
| new | 新发现的资产 | 加入登记 |

## 资产关联规则

1. Web 服务与 Flag 系统关联：Flag 通过 Web 接口暴露时，两者为强关联。
2. 数据库与文件关联：config.php 中的 DB 配置决定了数据库资产的连接方式。
3. 缓存与会话关联：session_save_path 指向 Redis 或文件系统决定了会话存储方式。
4. 定时任务与持久化关联：如果 crontab 中存在写入操作的定时任务，可能被利用做持久化后门。

## 与 awd-web 的集成

```
awd-web scan (findings)
       ↓
awd-asset collect (资产发现)
       ↓
awd-asset register (资产登记)
       ↓
awd-web gen-attack (利用资产生成攻击脚本)
       ↓
awd-asset track (追踪资产变化)
       ↓
awd-asset export (赛后导出完整清单)
```

## 典型场景

### 场景 1：快速首轮
- 使用 `quick` 模式
- 30 秒内完成核心资产收集
- 输出 `quick_assets.json`

### 场景 2：防守轮
- 使用 `full` 模式
- 2 分钟内深度扫描
- 输出 `full_assets.json`
- 关注 critical/high 资产

### 场景 3：比赛中追踪
- 使用 `track` 模式
- 对比两轮资产变化
- 输出 `state_changes.json`

### 场景 4：赛后归档
- 使用 `export` 模式
- 生成多格式清单
- 输出到指定目录
