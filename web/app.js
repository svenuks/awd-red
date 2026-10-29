// AWD-Red Web Dashboard Frontend Controller

let parsedConfigCache = null;

function switchTab(tabId) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));

    const activeBtn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.getAttribute('onclick').includes(tabId));
    if (activeBtn) activeBtn.classList.add('active');

    const pane = document.getElementById(`tab-${tabId}`);
    if (pane) pane.classList.add('active');

    if (tabId === 'dispatch') fetchExecutionLogs();
    if (tabId === 'vulns') fetchVulns();
    if (tabId === 'pocs') fetchPocs();
    if (tabId === 'import') fetchSettingsAndTargets();
    if (tabId === 'logs') fetchLogs();
}

function formatCountdown(sec) {
    if (sec <= 0) return '00:00';
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
}

// 1. 实时状态心跳
async function fetchStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();

        // 轮次与倒计时
        if (data.is_active) {
            document.getElementById('currentRound').innerText = `ROUND ${data.current_round}`;
            document.getElementById('roundStatusText').innerText = `比赛进行中 (已执行 ${data.last_executed_round} 轮)`;
            document.getElementById('countdownTimer').innerText = formatCountdown(data.seconds_to_next);
        } else {
            document.getElementById('currentRound').innerText = `未开始`;
            document.getElementById('roundStatusText').innerText = `距离开赛还有`;
            document.getElementById('countdownTimer').innerText = formatCountdown(data.seconds_to_next);
        }

        document.getElementById('roundDurationText').innerText = `${data.round_duration}s`;

        // 开关按钮
        const schedEl = document.getElementById('schedState');
        schedEl.innerText = data.scheduler_enabled ? '运行中' : '已暂停';
        schedEl.className = data.scheduler_enabled ? 'text-green' : 'text-yellow';

        const watchEl = document.getElementById('watchState');
        watchEl.innerText = data.watcher_enabled ? '运行中' : '已暂停';
        watchEl.className = data.watcher_enabled ? 'text-green' : 'text-yellow';

        const autoTriggerEl = document.getElementById('autoTriggerState');
        if (autoTriggerEl) {
            autoTriggerEl.innerText = data.auto_trigger_on_new_poc ? '开启' : '关闭';
            autoTriggerEl.className = data.auto_trigger_on_new_poc ? 'text-green' : 'text-muted';
        }

        // 调度控制看板状态
        const isInterval = (data.schedule_mode === 'interval');
        const modeBadge = document.getElementById('schedModeBadge');
        if (modeBadge) {
            modeBadge.innerText = isInterval ? '⏱️ 10分钟自动间隔循环' : '🕒 绝对时间模式 (开赛: 13:30)';
            modeBadge.className = isInterval ? 'badge-mode' : 'badge-mode text-yellow';
        }

        const execBadge = document.getElementById('schedExecBadge');
        if (execBadge) {
            if (data.is_executing_round) {
                execBadge.innerText = `⚡ 正在并发执行第 ${data.current_round} 轮`;
                execBadge.className = 'badge-status status-running';
            } else {
                execBadge.innerText = data.scheduler_enabled ? '💤 等待下轮调度' : '⏸️ 调度已暂停';
                execBadge.className = 'badge-status status-idle';
            }
        }

        const workerBadge = document.getElementById('schedWorkerBadge');
        if (workerBadge) {
            workerBadge.innerText = `并发任务: ${data.active_tasks || 0} / ${data.global_concurrency || 128}`;
        }

        const pauseBtn = document.getElementById('btnSchedPauseToggle');
        if (pauseBtn) {
            pauseBtn.innerHTML = `<span>${data.scheduler_enabled ? '⏸️ 暂停调度' : '▶️ 恢复调度'}</span>`;
        }

        const switchModeBtn = document.getElementById('btnSwitchSchedMode');
        if (switchModeBtn) {
            switchModeBtn.innerHTML = `<span>${isInterval ? '🕒 切换为13:30比赛定时' : '⏱️ 切换为10分钟间隔循环'}</span>`;
        }

        // 轮次进度条
        const pBar = document.getElementById('roundProgressBar');
        if (pBar) {
            pBar.style.width = `${data.progress_percent}%`;
            if (data.is_executing_round) {
                pBar.classList.add('executing');
            } else {
                pBar.classList.remove('executing');
            }
        }
        const elElapsed = document.getElementById('roundElapsedText');
        if (elElapsed) elElapsed.innerText = formatCountdown(data.elapsed_sec);
        const elTotal = document.getElementById('roundTotalText');
        if (elTotal) elTotal.innerText = formatCountdown(data.round_duration);
        const elPct = document.getElementById('roundPercentText');
        if (elPct) elPct.innerText = `${data.progress_percent}%`;

        const elHint = document.getElementById('roundCycleHint');
        if (elHint) {
            if (data.is_executing_round) {
                elHint.innerText = `⚡ 第 ${data.current_round} 轮任务执行中 (并发: ${data.active_tasks || 0})...`;
                elHint.className = 'text-green font-bold';
            } else if (!data.scheduler_enabled) {
                elHint.innerText = '⏸️ 自动调度已暂停，可手动点立即跑一轮';
                elHint.className = 'text-yellow';
            } else {
                elHint.innerText = `🟢 10分钟自动调度正常，将在 ${formatCountdown(data.seconds_to_next)} 后自动执行下轮`;
                elHint.className = 'text-muted';
            }
        }

        // 统计数据
        const stats = data.stats || {};
        document.getElementById('statReadyPocs').innerText = stats.ready_pocs || 0;
        document.getElementById('statTotalPocs').innerText = stats.total_pocs || 0;
        document.getElementById('statTargets').innerText = data.target_count || 0;
        document.getElementById('statTotalFlags').innerText = stats.total_flags || 0;
        document.getElementById('statSubmittedSuccess').innerText = stats.submitted_success || 0;

        // 漏洞统计
        const totalV = stats.total_vulns || 0;
        document.getElementById('statTotalVulns').innerText = totalV;
        document.getElementById('statVerifiedVulns').innerText = stats.verified_vulns || 0;
        document.getElementById('tabVulnCount').innerText = totalV;

        document.getElementById('connDot').className = 'dot live';
        document.getElementById('connText').innerText = '系统在线';

    } catch (e) {
        document.getElementById('connDot').className = 'dot';
        document.getElementById('connText').innerText = '连接中断';
    }
}

// 2. 开关与控制
async function toggleScheduler() {
    await fetch('/api/toggle_scheduler', { method: 'POST' });
    fetchStatus();
}

async function toggleWatcher() {
    await fetch('/api/toggle_watcher', { method: 'POST' });
    fetchStatus();
}

async function toggleAutoTrigger() {
    await fetch('/api/toggle_auto_trigger', { method: 'POST' });
    fetchStatus();
}

let autoScrollEnabled = true;
let logReverseOrder = true; // 默认倒序：最新在最顶部
let currentLogFilter = 'all';
let rawExecutionLogLines = [];
let fastLogTimer = null;

function toggleAutoScroll() {
    autoScrollEnabled = !autoScrollEnabled;
    const el = document.getElementById('autoScrollState');
    if (el) el.innerText = autoScrollEnabled ? '开' : '关';
}

function toggleLogOrder() {
    logReverseOrder = !logReverseOrder;
    const el = document.getElementById('logOrderState');
    if (el) el.innerText = logReverseOrder ? '倒序(最新在上)' : '正序(最新在下)';
    const sysEl = document.getElementById('sysLogOrderState');
    if (sysEl) sysEl.innerText = logReverseOrder ? '倒序(最新在上)' : '正序(最新在下)';
    renderExecutionTerminal();
    fetchLogs();
}

function toggleSysLogOrder() {
    toggleLogOrder();
}

function setLogFilter(filter) {
    currentLogFilter = filter;
    const btnAll = document.getElementById('btnFilterAll');
    const btnHits = document.getElementById('btnFilterHits');
    const btnWarn = document.getElementById('btnFilterWarn');
    if (btnAll) btnAll.className = `btn btn-sm btn-outline ${filter === 'all' ? 'active' : ''}`;
    if (btnHits) btnHits.className = `btn btn-sm btn-outline ${filter === 'hits' ? 'active' : ''}`;
    if (btnWarn) btnWarn.className = `btn btn-sm btn-outline ${filter === 'warn' ? 'active' : ''}`;
    renderExecutionTerminal();
}

function clearTerminal() {
    rawExecutionLogLines = [];
    const term = document.getElementById('executionTerminal');
    if (term) term.innerHTML = '<div class="terminal-empty text-muted text-center" style="padding: 30px;">终端日志已清空</div>';
}

function renderExecutionTerminal() {
    const term = document.getElementById('executionTerminal');
    if (!term) return;

    if (!rawExecutionLogLines || rawExecutionLogLines.length === 0) {
        term.innerHTML = '<div class="terminal-empty text-muted text-center" style="padding: 40px;">暂无日志输出</div>';
        return;
    }

    let filtered = rawExecutionLogLines;
    if (currentLogFilter === 'hits') {
        filtered = rawExecutionLogLines.filter(l => l.includes('[HIT]') || l.includes('[NEW FLAG]') || l.includes('🚩') || l.includes('🎯') || l.includes('[SUBMISSION]'));
    } else if (currentLogFilter === 'warn') {
        filtered = rawExecutionLogLines.filter(l => l.includes('TIMEOUT') || l.includes('ERROR') || l.includes('failed') || l.includes('WARNING') || l.includes('异常') || l.includes('⌛'));
    }

    if (filtered.length === 0) {
        term.innerHTML = `<div class="terminal-empty text-muted text-center" style="padding: 30px;">当前过滤条件【${currentLogFilter}】下暂无日志</div>`;
        return;
    }

    // 倒序处理：最新日志显示在最上面
    let displayLines = logReverseOrder ? [...filtered].reverse() : filtered;

    term.innerHTML = displayLines.map(line => {
        let cls = 'log-line';
        if (line.includes('[NEW FLAG]') || line.includes('🚩')) cls += ' log-flag';
        else if (line.includes('[HIT]') || line.includes('🎯')) cls += ' log-hit';
        else if (line.includes('[SUBMISSION]')) cls += ' log-sub';
        else if (line.includes('[Round Trigger]') || line.includes('Scheduled')) cls += ' log-trigger';
        else if (line.includes('[Round') && line.includes('Finished]')) cls += ' log-finish';
        else if (line.includes('TIMEOUT') || line.includes('⌛')) cls += ' log-warn';
        else if (line.includes('ERROR') || line.includes('failed')) cls += ' log-err';
        else if (line.includes('[OK]') || line.includes('✔')) cls += ' log-ok';

        return `<div class="${cls}">${escapeHtml(line)}</div>`;
    }).join('');

    if (autoScrollEnabled) {
        term.scrollTop = logReverseOrder ? 0 : term.scrollHeight;
    }
}

async function fetchExecutionLogs() {
    try {
        const res = await fetch('/api/logs');
        const data = await res.json();
        const logsText = data.logs || '';
        const lines = logsText.split('\n').filter(l => l.trim().length > 0);
        rawExecutionLogLines = lines;
        renderExecutionTerminal();
    } catch (e) {
        console.error("fetchExecutionLogs error:", e);
    }
}

async function startIntervalScheduler() {
    if (!confirm('确认启动 10 分钟自动轮训？\n\n系统将以当前时间为基准，立即开始第 1 轮并发测试，并每隔 10 分钟自动调度下一轮。')) return;
    try {
        switchTab('dispatch');
        if (fastLogTimer) clearInterval(fastLogTimer);
        let ticks = 0;
        fastLogTimer = setInterval(async () => {
            ticks++;
            await fetchExecutionLogs();
            await fetchStatus();
            if (ticks > 24) {
                clearInterval(fastLogTimer);
                fastLogTimer = null;
            }
        }, 500);

        const res = await fetch('/api/scheduler/start_interval', { method: 'POST' });
        const data = await res.json();
        await fetchStatus();
        await fetchExecutionLogs();
    } catch (e) {
        alert('启动失败: ' + e);
    }
}

async function toggleScheduleMode() {
    try {
        const res = await fetch('/api/scheduler/toggle_mode', { method: 'POST' });
        const data = await res.json();
        alert(data.message || '调度模式已切换！');
        fetchStatus();
    } catch (e) {
        alert('切换失败: ' + e);
    }
}

async function triggerRunRound() {
    if (!confirm('确认立即手动触发执行一轮 PoC 任务？')) return;
    try {
        switchTab('dispatch');
        if (fastLogTimer) clearInterval(fastLogTimer);
        let ticks = 0;
        fastLogTimer = setInterval(async () => {
            ticks++;
            await fetchExecutionLogs();
            await fetchStatus();
            if (ticks > 24) {
                clearInterval(fastLogTimer);
                fastLogTimer = null;
            }
        }, 500);

        const res = await fetch('/api/trigger_round', { method: 'POST' });
        const data = await res.json();
        await fetchStatus();
        await fetchExecutionLogs();
    } catch (e) {
        alert('触发失败: ' + e);
    }
}

// 3. Flag 列表拉取
async function fetchFlags() {
    try {
        const res = await fetch('/api/flags');
        const list = await res.json();
        const tbody = document.getElementById('flagsTableBody');

        if (!list || list.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">暂无捕获 Flag</td></tr>';
            return;
        }

        tbody.innerHTML = list.map(item => {
            const respStr = item.submit_response || '';
            const shortResp = respStr.length > 50 ? respStr.substring(0, 50) + '...' : respStr;
            let statusBadgeClass = 'badge-disabled';
            if (item.submit_status === 'success') statusBadgeClass = 'badge-ready';
            else if (item.submit_status === 'failed') statusBadgeClass = 'badge-failed';
            else if (item.submit_status === 'duplicate') statusBadgeClass = 'badge-pending';
            else if (item.submit_status === 'pending') statusBadgeClass = 'badge-mode';

            return `
            <tr>
                <td class="font-mono text-cyan font-bold" style="white-space: nowrap;">${escapeHtml(item.flag_val)}</td>
                <td><span class="badge badge-pending">R${item.round_num}</span></td>
                <td>${escapeHtml(item.target_ip)}</td>
                <td>${escapeHtml(item.poc_name)}</td>
                <td><span class="badge ${statusBadgeClass}">${escapeHtml(item.submit_status)}</span></td>
                <td class="font-mono text-muted" style="max-width: 280px; word-break: break-all; font-size: 11px;" title="${escapeHtml(respStr)}">${escapeHtml(shortResp || '-')}</td>
                <td class="text-muted" style="white-space: nowrap; font-size: 12px;">${item.found_at}</td>
                <td>
                    <button class="btn btn-sm btn-outline" style="padding: 2px 8px; font-size: 11px;" onclick="resubmitSingleFlag('${item.flag_hash}')">🚀 重提</button>
                </td>
            </tr>
            `;
        }).join('');
    } catch (e) {
        console.error(e);
    }
}

async function resubmitSingleFlag(flagHash) {
    try {
        const res = await fetch('/api/flags/resubmit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ flag_hash: flagHash })
        });
        const data = await res.json();
        alert(data.message || '重提完成！');
        await fetchFlags();
        await fetchStatus();
    } catch (e) {
        alert('重提请求失败: ' + e);
    }
}

async function resubmitAllFlags() {
    if (!confirm('确认批量重新提交所有未成功的 Flag 吗？')) return;
    try {
        const res = await fetch('/api/flags/resubmit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const data = await res.json();
        alert(data.message || '批量重提完成！');
        await fetchFlags();
        await fetchStatus();
    } catch (e) {
        alert('批量重提失败: ' + e);
    }
}

async function clearAllFlags() {
    if (!confirm('⚠️ 危险操作确认：\n\n确认清空所有已捕获的 Flag 记录吗？\n清空后将重置提交状态及去重历史，后续轮次可重新捕获与提交。')) return;
    try {
        const res = await fetch('/api/flags/clear', { method: 'POST' });
        const data = await res.json();
        alert(data.message || '已清空 Flag 记录');
        fetchFlags();
        fetchStatus();
    } catch (e) {
        alert('清空失败: ' + e);
    }
}

// 4. Tasks 任务列表拉取
async function fetchTasks() {
    try {
        const res = await fetch('/api/tasks');
        const list = await res.json();
        const tbody = document.getElementById('tasksTableBody');

        if (!list || list.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">暂无任务事件</td></tr>';
            return;
        }

        tbody.innerHTML = list.map(t => `
            <tr>
                <td><span class="badge badge-${t.status}">${t.status}</span></td>
                <td class="font-mono">${escapeHtml(t.target_ip)}</td>
                <td>${escapeHtml(t.poc_name)}</td>
                <td class="text-muted">${t.duration_ms}ms</td>
                <td class="font-mono text-muted" title="${escapeHtml(t.stdout || t.stderr || '')}">
                    ${escapeHtml((t.flag_captured ? '🚩 ' + t.flag_captured : (t.stdout || t.stderr || '')).slice(0, 36))}...
                </td>
            </tr>
        `).join('');
    } catch (e) {
        console.error(e);
    }
}

// 4.1 漏洞库管理
async function fetchVulns() {
    try {
        const res = await fetch('/api/vulns');
        const list = await res.json();
        const tbody = document.getElementById('vulnsTableBody');

        if (!list || list.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">漏洞库暂无数据，可运行 <code>awd_vulscan.py</code> 自动审计导入</td></tr>';
            return;
        }

        tbody.innerHTML = list.map(v => {
            const isVerified = v.verified === 1;
            const verifiedBadge = isVerified 
                ? '<span class="badge badge-success">🟢 已存活</span>' 
                : '<span class="badge badge-disabled">⚪ 未验证</span>';

            const levelColor = v.level >= 4 ? 'badge-failed' : (v.level === 3 ? 'badge-pending' : 'badge-disabled');
            const levelBadge = `<span class="badge ${levelColor}">Level ${v.level}</span>`;

            const loc = `${escapeHtml(v.file)}:${v.line}`;
            const param = v.param ? `<code>${escapeHtml(v.param)}</code>` : '<span class="text-muted">-</span>';
            const hint = v.poc_hint ? escapeHtml(v.poc_hint) : '<span class="text-muted">-</span>';

            return `
                <tr>
                    <td>${verifiedBadge}</td>
                    <td>${levelBadge}</td>
                    <td><strong class="text-cyan">${escapeHtml(v.vuln_type || v.category || '后门')}</strong></td>
                    <td class="font-mono" title="${loc}">${loc}</td>
                    <td>${param}</td>
                    <td class="font-mono text-muted" style="max-width:240px; word-break:break-all;" title="${hint}">${hint}</td>
                    <td class="text-muted">${v.discovered_at || ''}</td>
                    <td>
                        <button class="btn btn-sm btn-ghost" onclick="copyText('${escapeHtml(v.poc_hint || v.param || '')}')">复制载荷</button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (e) {
        console.error(e);
    }
}

async function clearVulns() {
    if (!confirm('确认清空新平台的漏洞库数据？')) return;
    await fetch('/api/vulns/clear', { method: 'POST' });
    fetchVulns();
    fetchStatus();
}

function copyText(txt) {
    if (!txt) return alert('无内容可复制');
    navigator.clipboard.writeText(txt).then(() => {
        alert('已复制到剪贴板: ' + txt);
    }).catch(() => {
        prompt('请手动复制:', txt);
    });
}

// 5. PoC 列表管理
async function fetchPocs() {
    try {
        const res = await fetch('/api/pocs');
        const list = await res.json();
        const tbody = document.getElementById('pocsTableBody');

        if (!list || list.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">尚未发现有效 PoC，可向 <code>pocs/incoming/</code> 放入文件</td></tr>';
            return;
        }

        tbody.innerHTML = list.map(p => {
            const isReady = (p.status === 'ready');
            const isDisabled = (p.status === 'disabled');

            let statusBadge = `<span class="badge badge-${p.status}">${p.status.toUpperCase()}</span>`;
            if (isReady) {
                statusBadge = '<span class="badge badge-ready">🟢 启用生效中</span>';
            } else if (isDisabled) {
                statusBadge = '<span class="badge badge-disabled">⚪ 已禁用</span>';
            } else if (p.status === 'failed') {
                statusBadge = '<span class="badge badge-failed">🔴 校验失败</span>';
            }

            const actionBtn = isReady 
                ? `<button class="btn btn-sm btn-outline text-red" onclick="togglePoc('${p.name}', false)">⛔ 禁用</button>`
                : `<button class="btn btn-sm btn-success" onclick="togglePoc('${p.name}', true)">▶️ 启用</button>`;

            const deleteBtn = `<button class="btn btn-sm btn-ghost text-red" onclick="deleteSinglePoc('${p.name}')" title="删除此 PoC 脚本">🗑️</button>`;

            const callCount = p.call_count || 0;
            const successCount = p.success_count || 0;
            const flagsCount = p.flags_count || 0;
            const successRate = callCount > 0 ? ((successCount / callCount) * 100).toFixed(0) : 0;

            const callStatsBadge = `
                <div style="line-height: 1.4;">
                    <span style="font-weight: 600; font-size: 13px;">调用 ${callCount} 次</span>
                    <span style="color: var(--success); font-weight: 600;"> (成 ${successCount})</span>
                    ${flagsCount > 0 ? `<div style="font-size: 11px; color: var(--accent); font-weight: bold;">🚩 捕获 ${flagsCount} 个Flag</div>` : ''}
                </div>
            `;

            return `
                <tr>
                    <td>${statusBadge}</td>
                    <td class="font-bold">${escapeHtml(p.name)}</td>
                    <td>${callStatsBadge}</td>
                    <td>v${p.version}</td>
                    <td><code>${escapeHtml(p.filename)}</code></td>
                    <td class="font-mono text-muted">${(p.file_hash || '').slice(0, 12)}...</td>
                    <td class="text-muted">${p.updated_at}</td>
                    <td>
                        <div style="display: flex; gap: 6px; align-items: center;">
                            ${actionBtn}
                            ${deleteBtn}
                        </div>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (e) {
        console.error(e);
    }
}

async function syncPocs() {
    const res = await fetch('/api/pocs/sync', { method: 'POST' });
    const data = await res.json();
    alert(`扫描完成！提升生效: ${data.promoted.length} 个, 更新: ${data.updated.length} 个, 失败: ${data.failed.length} 个`);
    fetchPocs();
    fetchStatus();
}

async function deleteSinglePoc(name) {
    if (!confirm(`确认删除 PoC [${name}] 并移除对应磁盘文件？`)) return;
    try {
        const res = await fetch('/api/pocs/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name })
        });
        const data = await res.json();
        alert(data.message || '删除成功');
        fetchPocs();
        fetchStatus();
    } catch (e) {
        alert('删除失败: ' + e);
    }
}

async function clearAllPocs() {
    if (!confirm('⚠️ 危险操作确认：\n\n确认彻底清空所有 PoC 吗？\n将从 ready/、incoming/、disabled/ 等目录中删除所有 PoC 文件，并重置数据库 PoC 记录。')) return;
    try {
        const res = await fetch('/api/pocs/clear', { method: 'POST' });
        const data = await res.json();
        alert(data.message || '已清空所有 PoC');
        fetchPocs();
        fetchStatus();
    } catch (e) {
        alert('清空失败: ' + e);
    }
}

async function togglePoc(name, enable) {
    try {
        const res = await fetch('/api/pocs/toggle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, enable })
        });
        const data = await res.json();
        if (!data.success) {
            alert(`操作失败: 未能${enable ? '启用' : '禁用'} PoC ${name}`);
        }
        await fetchPocs();
        await fetchStatus();
    } catch (e) {
        alert('网络请求失败: ' + e);
    }
}

// 6. 智能解析导入
async function smartParseText() {
    const text = document.getElementById('rawNoticeInput').value.trim();
    if (!text) return alert('请先粘贴比赛说明或公告内容！');

    const res = await fetch('/api/smart_parse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text })
    });
    const parsed = await res.json();
    parsedConfigCache = parsed;

    document.getElementById('parsePreviewBox').style.display = 'block';
    document.getElementById('parsePreviewContent').innerText = JSON.stringify(parsed, null, 2);
    document.getElementById('btnApplyParsed').style.display = 'inline-block';
}

async function applyParsedConfig() {
    if (!parsedConfigCache) return;
    if (!confirm(`确认应用已识别的 ${parsedConfigCache.target_count} 个靶机 IP 及提交接口配置？`)) return;

    const res = await fetch('/api/apply_parsed', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(parsedConfigCache)
    });
    const result = await res.json();
    alert(result.message || '配置已应用！');
    fetchSettingsAndTargets();
    fetchStatus();
}

// 7. 手动设置与 Targets
let currentExpandedTargets = [];
let targetViewMode = 'grid'; // 'grid' | 'text'

async function fetchTargetsData() {
    try {
        const res = await fetch('/api/targets');
        const data = await res.json();
        
        const inputElem = document.getElementById('targetsListInput');
        if (inputElem) {
            inputElem.value = (data.raw_targets || []).join('\n');
        }
        
        currentExpandedTargets = data.expanded_targets || [];
        renderGeneratedTargets(currentExpandedTargets);
        updateTargetsBadges(currentExpandedTargets.length);
    } catch (e) {
        console.error("fetchTargetsData error:", e);
    }
}

async function fetchSettingsAndTargets() {
    try {
        const res = await fetch('/api/settings');
        const data = await res.json();

        document.getElementById('cfgStartTime').value = data.settings.competition_start_time || '';
        document.getElementById('cfgDuration').value = data.settings.round_duration_sec || 600;
        document.getElementById('cfgPocConcurrency').value = data.settings.poc_concurrency || 64;
        document.getElementById('cfgTimeout').value = data.settings.task_timeout_sec || 3.0;
        document.getElementById('cfgFlagPattern').value = data.settings.flag_pattern || '';
        document.getElementById('cfgGetFlagCmd').value = data.settings.get_flag_cmd || '';
        
        await fetchTargetsData();
        await fetchSubmitterConfig();
    } catch (e) {
        console.error("fetchSettingsAndTargets error:", e);
    }
}

// 7.1 Submitter 智能请求包全量导入与配置管理
async function importRawSubmitterPackage() {
    const rawInput = document.getElementById('subRawPackage');
    const alertBox = document.getElementById('subRawImportAlert');
    if (!rawInput) return;

    const raw = rawInput.value.trim();
    if (!raw) {
        alert('请先在输入框中粘贴完整的请求包（PowerShell / cURL / 原始 HTTP）！');
        return;
    }

    try {
        const res = await fetch('/api/submitter/import_raw', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ raw })
        });
        const result = await res.json();

        if (result.success) {
            await fetchSubmitterConfig();
            if (alertBox) {
                alertBox.style.display = 'block';
                alertBox.style.background = 'rgba(16, 185, 129, 0.2)';
                alertBox.style.border = '1px solid #10b981';
                alertBox.style.color = '#34d399';
                const headerCount = Object.keys(result.config.headers || {}).length;
                alertBox.innerHTML = `<strong>✔ 自动解析并应用成功！</strong> 接口: <code>${result.config.url}</code> | 请求头: <code>${headerCount} 项</code> | 模板: <code>${result.config.body_template}</code>`;
            }
            alert('🎉 恭喜！请求包已自动解析完成，并全量更新保存到提交器配置中！');
        } else {
            if (alertBox) {
                alertBox.style.display = 'block';
                alertBox.style.background = 'rgba(239, 68, 68, 0.2)';
                alertBox.style.border = '1px solid #ef4444';
                alertBox.style.color = '#f87171';
                alertBox.innerHTML = `<strong>✖ 解析失败：</strong> ${result.message || '未知错误'}`;
            }
            alert('解析失败：' + (result.message || '未知错误'));
        }
    } catch (e) {
        alert('请求接口失败：' + e.message);
    }
}

function clearRawSubmitterPackage() {
    const rawInput = document.getElementById('subRawPackage');
    const alertBox = document.getElementById('subRawImportAlert');
    if (rawInput) rawInput.value = '';
    if (alertBox) {
        alertBox.style.display = 'none';
        alertBox.innerHTML = '';
    }
}

async function fetchSubmitterConfig() {
    try {
        const res = await fetch('/api/submitter');
        const data = await res.json();
        
        const enabledElem = document.getElementById('subEnabled');
        if (enabledElem) enabledElem.checked = !!data.enabled;
        const urlElem = document.getElementById('subUrl');
        if (urlElem) urlElem.value = data.url || '';
        const methodElem = document.getElementById('subMethod');
        if (methodElem) methodElem.value = (data.method || 'POST').toUpperCase();
        const successElem = document.getElementById('subSuccessKeyword');
        if (successElem) successElem.value = data.success_keyword || '';
        const headersElem = document.getElementById('subHeaders');
        if (headersElem) headersElem.value = JSON.stringify(data.headers || {}, null, 2);
        const bodyElem = document.getElementById('subBodyTemplate');
        if (bodyElem) bodyElem.value = data.body_template || '{"matchId":"2146","exerciseId":23653,"flag":"{flag}"}';

        updateSubmitterBadge(!!data.enabled);
    } catch (e) {
        console.error("fetchSubmitterConfig error:", e);
    }
}

function updateSubmitterBadge(enabled) {
    const badge = document.getElementById('submitterStatusBadge');
    if (badge) {
        badge.innerText = enabled ? '🟢 自动提交已开启' : '⚪ 自动提交已禁用';
        badge.className = enabled ? 'badge badge-ready' : 'badge badge-disabled';
    }
}

async function saveSubmitterConfig() {
    let headers = {};
    try {
        const hText = document.getElementById('subHeaders').value.trim();
        if (hText) headers = JSON.parse(hText);
    } catch (e) {
        return alert('请求头 Headers 格式错误，必须是合法的 JSON 格式！\n' + e);
    }

    const payload = {
        enabled: document.getElementById('subEnabled').checked,
        url: document.getElementById('subUrl').value.trim(),
        method: document.getElementById('subMethod').value,
        format: 'json',
        headers: headers,
        body_template: document.getElementById('subBodyTemplate').value.trim(),
        success_keyword: document.getElementById('subSuccessKeyword').value.trim(),
        duplicate_keyword: 'repeat|duplicate|already|重复|已提交'
    };

    try {
        const res = await fetch('/api/submitter', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const result = await res.json();
        alert(result.message || '提交器配置已保存！');
        updateSubmitterBadge(payload.enabled);
        fetchStatus();
    } catch (e) {
        alert('保存提交器失败: ' + e);
    }
}

async function testSubmitter() {
    const box = document.getElementById('subTestResultBox');
    const badge = document.getElementById('subTestStatusBadge');
    const content = document.getElementById('subTestResultContent');
    
    const testFlag = prompt('请输入要测试提交的 Flag 值（留空则使用演示 Flag）：', 'flag{test_demo_flag_123456}') || 'flag{test_demo_flag_123456}';

    box.style.display = 'block';
    badge.className = 'badge badge-pending';
    badge.innerText = '测试中...';
    content.innerText = '正在向比赛裁判平台发送测试请求...';

    try {
        const res = await fetch('/api/submitter/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ flag: testFlag })
        });
        const data = await res.json();

        if (data.status === 'success') {
            badge.className = 'badge badge-ready';
            badge.innerText = '成功 SUCCESS';
        } else if (data.status === 'duplicate') {
            badge.className = 'badge badge-pending';
            badge.innerText = '重复 DUPLICATE';
        } else if (data.status === 'skipped') {
            badge.className = 'badge badge-disabled';
            badge.innerText = '已跳过 SKIPPED';
        } else {
            badge.className = 'badge badge-failed';
            badge.innerText = '失败 FAILED';
        }
        content.innerText = `[提交状态]: ${data.status}\n[返回结果]: ${data.response}`;
    } catch (e) {
        badge.className = 'badge badge-failed';
        badge.innerText = '请求异常';
        content.innerText = '测试请求失败: ' + e;
    }
}

async function saveSettings() {
    const payload = {
        competition_start_time: document.getElementById('cfgStartTime').value.trim(),
        round_duration_sec: parseInt(document.getElementById('cfgDuration').value),
        poc_concurrency: parseInt(document.getElementById('cfgPocConcurrency').value),
        task_timeout_sec: parseFloat(document.getElementById('cfgTimeout').value),
        flag_pattern: document.getElementById('cfgFlagPattern').value.trim(),
        get_flag_cmd: document.getElementById('cfgGetFlagCmd').value.trim()
    };

    const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    const result = await res.json();
    alert(result.message || '设置已保存');
    fetchStatus();
}

async function saveTargets() {
    const text = document.getElementById('targetsListInput').value;
    const lines = text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));

    const res = await fetch('/api/targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targets: lines })
    });
    const result = await res.json();
    alert(result.message || '目标列表已保存');
    if (result.expanded_targets) {
        currentExpandedTargets = result.expanded_targets;
        renderGeneratedTargets(currentExpandedTargets);
        updateTargetsBadges(currentExpandedTargets.length);
    } else {
        await fetchTargetsData();
    }
    fetchStatus();
}

async function expandTargetsToInput() {
    const text = document.getElementById('targetsListInput').value;
    const lines = text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    if (!lines.length) {
        return alert('当前没有输入任何目标 IP 或网段规则！');
    }

    try {
        const res = await fetch('/api/targets/expand', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ targets: lines })
        });
        const result = await res.json();
        if (result.expanded_targets && result.expanded_targets.length > 0) {
            currentExpandedTargets = result.expanded_targets;
            renderGeneratedTargets(currentExpandedTargets);
            updateTargetsBadges(currentExpandedTargets.length);
            
            if (confirm(`已成功解析并展开出 ${result.count} 台目标靶机！\n\n是否将展开后的全部独立 IP 直接替换填入输入框？`)) {
                document.getElementById('targetsListInput').value = result.expanded_targets.join('\n');
            }
        } else {
            alert('未能识别到有效的 IPv4 地址，请检查格式（如 192.168.1.1-255 或 192.168.1.0/24）。');
        }
    } catch (e) {
        alert('展开目标失败: ' + e);
    }
}

async function clearAllTargets() {
    if (!confirm('⚠️ 危险操作：确认清空所有目标靶机 IPv4 列表吗？\n\n清空后 targets.txt 将被重置，系统将停止对所有靶机的任务派发！')) {
        return;
    }

    try {
        const res = await fetch('/api/targets/clear', { method: 'POST' });
        const data = await res.json();
        alert(data.message || '目标列表已成功清空！');
        document.getElementById('targetsListInput').value = '';
        currentExpandedTargets = [];
        renderGeneratedTargets([]);
        updateTargetsBadges(0);
        await fetchStatus();
    } catch (e) {
        alert('清空目标失败: ' + e);
    }
}

function renderGeneratedTargets(targets) {
    const grid = document.getElementById('targetsTagGrid');
    const textElem = document.getElementById('targetsExpandedText');
    const countSpan = document.getElementById('generatedTargetCount');
    if (!grid) return;

    if (countSpan) countSpan.innerText = `共 ${targets.length} 台`;
    if (textElem) textElem.value = targets.join('\n');

    if (!targets || targets.length === 0) {
        grid.innerHTML = '<div class="text-muted text-center" style="grid-column: 1 / -1; padding: 20px;">暂无生成的目标靶机，请在上方输入规则或导入后点击保存</div>';
        return;
    }

    let html = '';
    targets.forEach((ip, idx) => {
        html += `<span class="target-chip" onclick="copyIp('${ip}')" title="点击复制 IP ${ip}"><span class="chip-idx">#${idx + 1}</span>${ip}</span>`;
    });
    grid.innerHTML = html;
}

function renderFilteredTargets() {
    const q = (document.getElementById('targetSearchInput')?.value || '').trim().toLowerCase();
    if (!q) {
        renderGeneratedTargets(currentExpandedTargets);
        return;
    }
    const filtered = currentExpandedTargets.filter(ip => ip.toLowerCase().includes(q));
    renderGeneratedTargets(filtered);
    const countSpan = document.getElementById('generatedTargetCount');
    if (countSpan) countSpan.innerText = `匹配 ${filtered.length} / ${currentExpandedTargets.length} 台`;
}

function copyIp(ip) {
    navigator.clipboard.writeText(ip).then(() => {
        alert(`已复制 IP: ${ip}`);
    }).catch(() => {
        prompt('请复制 IP:', ip);
    });
}

function copyAllGeneratedTargets() {
    if (!currentExpandedTargets || currentExpandedTargets.length === 0) {
        return alert('暂无生成的目标 IP 列表！');
    }
    const fullText = currentExpandedTargets.join('\n');
    navigator.clipboard.writeText(fullText).then(() => {
        alert(`已成功复制全部 ${currentExpandedTargets.length} 个目标 IP 至剪贴板！`);
    }).catch(() => {
        prompt('请复制全部 IP 列表:', fullText);
    });
}

function toggleTargetViewMode() {
    const grid = document.getElementById('targetsTagGrid');
    const textElem = document.getElementById('targetsExpandedText');
    const btn = document.getElementById('btnToggleTargetView');
    if (!grid || !textElem || !btn) return;

    if (targetViewMode === 'grid') {
        targetViewMode = 'text';
        grid.style.display = 'none';
        textElem.style.display = 'block';
        textElem.value = currentExpandedTargets.join('\n');
        btn.innerText = '切换为网格视图';
    } else {
        targetViewMode = 'grid';
        grid.style.display = 'grid';
        textElem.style.display = 'none';
        btn.innerText = '切换为文本视图';
    }
}

function updateTargetsBadges(count) {
    const badge = document.getElementById('targetsCountBadge');
    if (badge) {
        badge.innerText = `已生成: ${count} 台目标`;
        badge.className = count > 0 ? 'badge badge-ready' : 'badge badge-disabled';
    }
}

// 7.1 测试运行获取 Flag 命令
async function testRunGetFlagCmd() {
    const cmd = document.getElementById('cfgGetFlagCmd').value.trim();
    if (!cmd) return alert('请先输入获取 Flag 的命令（如 curl ...）！');

    const box = document.getElementById('getFlagResultBox');
    const badge = document.getElementById('getFlagStatusBadge');
    const content = document.getElementById('getFlagResultContent');

    box.style.display = 'block';
    badge.className = 'badge badge-pending';
    badge.innerText = '执行中...';
    content.innerText = '正在执行: ' + cmd + ' ...';

    try {
        const res = await fetch('/api/test_get_flag', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cmd })
        });
        const data = await res.json();

        if (data.success) {
            badge.className = 'badge badge-ready';
            badge.innerText = `成功 (${data.duration_ms}ms)`;
        } else {
            badge.className = 'badge badge-failed';
            badge.innerText = `失败 (${data.duration_ms}ms)`;
        }

        let flagsNotice = '';
        if (data.flags_found && data.flags_found.length > 0) {
            flagsNotice = `\n🚩 [识别到有效 Flag]: ${data.flags_found.join(', ')}\n\n`;
        }

        content.innerText = flagsNotice + (data.output || data.error || '无回显');
    } catch (e) {
        badge.className = 'badge badge-failed';
        badge.innerText = '网络异常';
        content.innerText = '请求失败: ' + e;
    }
}

// 8. 日志流
async function fetchLogs() {
    const res = await fetch('/api/logs');
    const data = await res.json();
    const consoleEl = document.getElementById('logConsole');
    if (!consoleEl) return;
    const lines = (data.logs || '').split('\n').filter(l => l.trim().length > 0);
    const displayLines = logReverseOrder ? [...lines].reverse() : lines;
    consoleEl.innerText = displayLines.join('\n') || '暂无日志输出';
    consoleEl.scrollTop = logReverseOrder ? 0 : consoleEl.scrollHeight;
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// 初始化轮询
fetchStatus();
fetchFlags();
fetchTasks();
fetchPocs();

setInterval(fetchStatus, 1000);
setInterval(fetchFlags, 3000);
setInterval(fetchTasks, 3000);
setInterval(() => {
    const pocsTab = document.getElementById('tab-pocs');
    if (pocsTab && pocsTab.classList.contains('active')) {
        fetchPocs();
    }
}, 3000);
setInterval(() => {
    const dispatchTab = document.getElementById('tab-dispatch');
    if (dispatchTab && dispatchTab.classList.contains('active')) {
        fetchExecutionLogs();
    }
}, 1500);
