/* 科研数据脱敏平台 — 前端控制台 */
'use strict';

const S = {
  route: 'overview',
  datasets: [],
  projects: [],
  currentDataset: null,
  fields: [],
  policy: null,
  releases: [],
  detectionEval: null,
  preview: null,
  policyDraft: null,
};

// ---------- api ----------

async function api(path, opts = {}) {
  const actor = document.getElementById('actor')?.value || '科研处管理员';
  // HTTP header values must be ISO-8859-1; percent-encode the Chinese actor name.
  const headers = Object.assign({ 'x-actor': encodeURIComponent(actor) }, opts.headers || {});
  if (opts.body && !(opts.body instanceof FormData)) {
    headers['content-type'] = 'application/json';
    opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch(path, { ...opts, headers });
  const ct = res.headers.get('content-type') || '';
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    if (ct.includes('json')) {
      try { msg = (await res.json()).error || msg; } catch (_) {}
    }
    throw new Error(msg);
  }
  if (ct.includes('json')) return res.json();
  return res;
}

function toast(msg, kind = '') {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = `toast show ${kind}`;
  clearTimeout(el._t);
  el._t = setTimeout(() => (el.className = 'toast'), 3200);
}

// ---------- helpers ----------

const esc = (s) =>
  String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

const pct = (x, d = 1) => (x == null || isNaN(x) ? '—' : `${(x * 100).toFixed(d)}%`);
const num = (x, d = 2) => (x == null || isNaN(x) ? '—' : Number(x).toFixed(d));

const STATUS = {
  registered: ['已登记', 'gray'],
  loaded: ['已载入', 'blue'],
  detected: ['已识别', 'blue'],
  configured: ['已配置', 'warn'],
  evaluated: ['已评估', 'warn'],
  pending: ['待审批', 'warn'],
  blocked: ['风险未通过', 'bad'],
  approved: ['已批准', 'ok'],
  rejected: ['已驳回', 'bad'],
};

const statusChip = (s) => {
  const [label, cls] = STATUS[s] || [s, 'gray'];
  return `<span class="chip ${cls}">${esc(label)}</span>`;
};

const PASS = (b) => (b ? '<span class="pass">通过</span>' : '<span class="fail">未通过</span>');

function el(html) {
  const t = document.createElement('template');
  t.innerHTML = html.trim();
  return t.content.firstElementChild;
}

function modal({ title, body, foot }) {
  const root = document.getElementById('modal-root');
  const back = el(`<div class="modal-back">
    <div class="modal">
      <div class="modal-head"><h3>${esc(title)}</h3><button class="ghost sm" data-close>✕</button></div>
      <div class="modal-body">${body}</div>
      <div class="modal-foot">${foot || '<button data-close>关闭</button>'}</div>
    </div>
  </div>`);
  root.appendChild(back);
  const close = () => back.remove();
  back.querySelectorAll('[data-close]').forEach((b) => (b.onclick = close));
  back.addEventListener('click', (e) => { if (e.target === back) close(); });
  return close;
}

function confirmBox(msg, onOk, okLabel = '确认') {
  const close = modal({
    title: '请确认',
    body: `<p class="small">${esc(msg)}</p>`,
    foot: `<button data-close>取消</button><button class="primary" id="ok-btn">${esc(okLabel)}</button>`,
  });
  document.getElementById('ok-btn').onclick = async () => {
    close();
    await onOk();
  };
}

function copyText(t) {
  navigator.clipboard?.writeText(t).then(() => toast('已复制', 'ok'));
}

// ---------- router ----------

const PAGES = {
  overview: ['总览', '脱敏与发布全流程工作台'],
  datasets: ['① 数据集登记', '登记来源、上传门诊/住院/自由文本数据'],
  fields: ['② 字段识别', '自动识别直接标识与文本内标识，可人工校正'],
  policy: ['③ 脱敏策略', '假名、日期平移、泛化与 k 匿名配置'],
  risk: ['④ 风险评估', 'k 匿名、再识别风险与统计量偏差校验'],
  approval: ['⑤ 发布审批', '审批通过后生成并导出脱敏发布包'],
  audit: ['审计追溯', '哈希链审计日志，可追溯到策略版本'],
  synthetic: ['测试数据与检出率', '生成含埋点真值的合成病历，统计检出率与误报率'],
};

function parseHash() {
  const m = location.hash.match(/^#\/([a-z]+)(?:\/([^/?]+))?/);
  return { route: m?.[1] || 'overview', id: m?.[2] || null };
}

async function navigate() {
  const { route, id } = parseHash();
  S.route = route;
  if (id) S.currentDataset = id;
  if (['fields', 'policy', 'risk', 'approval'].includes(route)) {
    if (!S.currentDataset && S.datasets[0]) S.currentDataset = S.datasets[0].id;
  }
  document.querySelectorAll('#nav a').forEach((a) => a.classList.toggle('active', a.dataset.route === route));
  const [title, sub] = PAGES[route] || ['未知页面', ''];
  document.getElementById('page-title').textContent = title;
  document.getElementById('page-sub').textContent = sub;
  document.getElementById('head-actions').innerHTML = '';
  const content = document.getElementById('content');
  content.innerHTML = '<div class="empty">加载中…</div>';
  try {
    if (route === 'overview') await renderOverview();
    else if (route === 'datasets') await renderDatasets();
    else if (route === 'fields') await renderFields();
    else if (route === 'policy') await renderPolicy();
    else if (route === 'risk') await renderRisk();
    else if (route === 'approval') await renderApproval();
    else if (route === 'audit') await renderAudit();
    else if (route === 'synthetic') await renderSynthetic();
  } catch (e) {
    content.innerHTML = `<div class="banner bad">加载失败：${esc(e.message)}</div>`;
  }
  refreshChain();
}

async function refreshChain() {
  try {
    const r = await api('/api/audit/verify');
    const el = document.getElementById('chain-status');
    el.textContent = r.chain_ok ? `审计链完整 · ${r.events} 条` : '审计链校验失败！';
    el.className = `chain ${r.chain_ok ? 'ok' : 'bad'}`;
  } catch (_) {}
}

// ---------- data loading ----------

async function loadDatasets() {
  const r = await api('/api/datasets');
  S.datasets = r.datasets;
  return S.datasets;
}
async function loadProjects() {
  const r = await api('/api/projects');
  S.projects = r.projects;
  return S.projects;
}

function datasetPicker(selected, onchange) {
  if (!S.datasets.length) return '<span class="muted small">暂无数据集，请先在「数据集登记」创建</span>';
  const sel = el(`<select>${S.datasets
    .map((d) => `<option value="${d.id}" ${d.id === selected ? 'selected' : ''}>${esc(d.name)} · ${d.row_count} 行</option>`)
    .join('')}</select>`);
  sel.onchange = () => onchange(sel.value);
  return sel;
}

// ---------- overview ----------

async function renderOverview() {
  const [stats] = await Promise.all([api('/api/stats'), loadDatasets(), loadProjects()]);
  const recent = await api('/api/releases');
  S.releases = recent.releases;
  const c = document.getElementById('content');
  c.innerHTML = `
    <div class="grid c4">
      <div class="stat"><div class="k">已登记数据集</div><div class="v">${stats.datasets}</div><div class="e">累计 ${stats.total_rows} 行</div></div>
      <div class="stat"><div class="k">脱敏发布次数</div><div class="v">${stats.releases}</div><div class="e">已批准 ${stats.approved} 次</div></div>
      <div class="stat"><div class="k">待处理</div><div class="v" style="color:#ffdf8a">${stats.pending}</div><div class="e">待审批发布</div></div>
      <div class="stat"><div class="k">风险拦截</div><div class="v" style="color:#ffb6b3">${stats.blocked}</div><div class="e">未达 k 匿名被阻止</div></div>
    </div>
    <div class="grid c2" style="margin-top:16px">
      <div class="card">
        <h2>工作流</h2>
        <p class="sub">从登记到发布共 5 步，每一步都有审计记录。</p>
        <div class="criteria">
          ${[
            ['① 数据集登记', '登记来源、上传门诊/住院/自由文本 CSV', '#/datasets'],
            ['② 字段识别', '自动识别姓名、身份证、手机、住址、病案号', '#/fields'],
            ['③ 脱敏策略', '假名规则、日期平移、泛化与 k 值', '#/policy'],
            ['④ 风险评估', 'k 匿名、再识别风险、统计量偏差', '#/risk'],
            ['⑤ 发布审批', '审批后生成发布包并写审计', '#/approval'],
          ].map(([t, d, h]) => `<a class="crit pass" href="${h}" style="text-decoration:none;color:inherit"><div class="name">${t}</div><div class="detail">${d}</div></a>`).join('')}
        </div>
      </div>
      <div class="card">
        <h2>核心保障</h2>
        <p class="sub">这些约束在服务端强制执行，不依赖前端。</p>
        <table>
          <tr><td>跨表跨批次同一患者</td><td class="right"><span class="chip ok">假名一致</span></td></tr>
          <tr><td>不同课题组</td><td class="right"><span class="chip ok">假名不同且不可关联</span></td></tr>
          <tr><td>日期平移</td><td class="right"><span class="chip ok">患者级整体偏移</span></td></tr>
          <tr><td>住院天数 / 用药间隔</td><td class="right"><span class="chip ok">保持不变</span></td></tr>
          <tr><td>k 匿名不达标</td><td class="right"><span class="chip bad">禁止导出</span></td></tr>
          <tr><td>审批与导出</td><td class="right"><span class="chip blue">全程审计哈希链</span></td></tr>
        </table>
      </div>
    </div>
    <div class="card">
      <h2>最近发布</h2>
      ${recent.releases.length ? `<div class="tbl-wrap"><table>
        <thead><tr><th>发布编号</th><th>数据集</th><th>课题组</th><th>k</th><th>最小等价类</th><th>状态</th><th>时间</th></tr></thead>
        <tbody>${recent.releases.slice(0, 8).map((r) => `<tr>
          <td class="mono tiny">${esc(r.id)}</td><td>${esc(r.dataset_name)}</td>
          <td>${esc(r.group_name)}</td><td>${r.k}</td>
          <td>${r.risk?.min_class_size ?? '—'}</td>
          <td>${statusChip(r.status)}</td><td class="tiny muted">${esc(r.created_at)}</td></tr>`).join('')}</tbody>
      </table></div>` : '<div class="empty"><div class="big">📦</div>还没有发布记录，先去登记数据集吧</div>'}
    </div>`;
}

// ---------- datasets ----------

async function renderDatasets() {
  await Promise.all([loadDatasets(), loadProjects()]);
  const c = document.getElementById('content');
  document.getElementById('head-actions').innerHTML = `
    <button class="primary" id="new-ds">＋ 登记数据集</button>
    <button id="gen-demo">生成演示数据</button>`;
  document.getElementById('new-ds').onclick = () => datasetModal();
  document.getElementById('gen-demo').onclick = async () => {
    const close = modal({
      title: '生成合成测试数据',
      body: `<div class="grid c2">
        <label class="f">患者例数<input id="gp" type="number" value="300" min="50"></label>
        <label class="f">随机种子<input id="gs" type="number" value="20260101"></label>
      </div><p class="sub" style="margin-top:10px">生成门诊/住院/用药/自由文本四类表，文本内埋入姓名、身份证、手机、住址、病案号等标识作为真值。</p>`,
      foot: `<button data-close>取消</button><button class="primary" id="gen-ok">生成</button>`,
    });
    document.getElementById('gen-ok').onclick = async () => {
      const patients = Number(document.getElementById('gp').value) || 300;
      const seed = Number(document.getElementById('gs').value) || 20260101;
      toast('正在生成…');
      try {
        const r = await api('/api/synthetic/generate', { method: 'POST', body: { patients, seed } });
        close();
        toast(`已生成 ${r.profile.patients} 例患者`, 'ok');
        await loadDatasets();
        location.hash = '#/fields/' + r.id;
      } catch (e) { toast(e.message, 'err'); }
    };
  };

  c.innerHTML = `
    <div class="banner info">🧪 没有真实数据也能跑通全流程：点击「生成演示数据」会创建含埋点真值的合成病历，并自动统计检出率与误报率。</div>
    <div class="card">
      <h2>数据集列表</h2>
      <p class="sub">登记后上传 CSV 或 ZIP（可含多张表），例如患者主索引、住院记录、门诊记录、临床文本。</p>
      ${S.datasets.length ? `<div class="tbl-wrap"><table>
        <thead><tr><th>名称</th><th>来源</th><th>负责人</th><th>文件</th><th>字段</th><th>行数</th><th>状态</th><th>操作</th></tr></thead>
        <tbody>${S.datasets.map((d) => `<tr>
          <td><strong>${esc(d.name)}</strong><div class="tiny muted">${esc(d.description || '')}</div></td>
          <td>${esc(d.source)}</td><td>${esc(d.owner || '—')}</td>
          <td>${d.file_count}</td><td>${d.field_count}</td><td>${d.row_count}</td>
          <td>${statusChip(d.status)}</td>
          <td class="nowrap">
            <button class="sm" data-up="${d.id}">上传</button>
            <button class="sm" data-view="${d.id}">预览</button>
            <button class="sm" data-fields="${d.id}">识别</button>
            <button class="sm danger" data-del="${d.id}">删除</button>
          </td></tr>`).join('')}</tbody>
      </table></div>` : '<div class="empty"><div class="big">🗂</div>还没有数据集</div>'}
    </div>
    <div class="card">
      <h2>合作课题组</h2>
      <p class="sub">不同课题组的假名相互独立，无法跨组关联同一患者。</p>
      <div class="row" style="margin-bottom:10px"><button class="sm" id="new-project">＋ 新建课题组</button></div>
      <div class="tbl-wrap"><table>
        <thead><tr><th>课题名称</th><th>课题组</th><th>联系人</th><th>发布次数</th></tr></thead>
        <tbody>${S.projects.map((p) => `<tr><td>${esc(p.name)}</td><td>${esc(p.group_name)}</td><td>${esc(p.contact || '—')}</td><td>${p.release_count}</td></tr>`).join('')}</tbody>
      </table></div>
    </div>`;

  c.querySelectorAll('[data-up]').forEach((b) => (b.onclick = () => uploadModal(b.dataset.up)));
  c.querySelectorAll('[data-view]').forEach((b) => (b.onclick = () => previewModal(b.dataset.view)));
  c.querySelectorAll('[data-fields]').forEach((b) => (b.onclick = () => { location.hash = '#/fields/' + b.dataset.fields; }));
  c.querySelectorAll('[data-del]').forEach((b) => (b.onclick = () => confirmBox('删除数据集将同时删除其文件、识别结果与发布记录（已批准发布不能删除）。确定？', async () => {
    try { await api('/api/datasets/' + b.dataset.del, { method: 'DELETE' }); toast('已删除', 'ok'); await renderDatasets(); } catch (e) { toast(e.message, 'err'); }
  }, '删除')));
  document.getElementById('new-project').onclick = () => projectModal();
}

function datasetModal() {
  const close = modal({
    title: '登记数据集',
    body: `<div class="grid c2">
      <label class="f">数据集名称 *<input id="d-name" placeholder="如：2024 年心内科住院队列"></label>
      <label class="f">数据来源 *<input id="d-source" placeholder="如：HIS 导出 / 病案室"></label>
      <label class="f">负责人<input id="d-owner" placeholder="如：信息科 张工"></label>
      <label class="f">说明<input id="d-desc" placeholder="用途、范围等"></label>
    </div>`,
    foot: `<button data-close>取消</button><button class="primary" id="d-ok">登记</button>`,
  });
  document.getElementById('d-ok').onclick = async () => {
    const body = {
      name: document.getElementById('d-name').value.trim(),
      source: document.getElementById('d-source').value.trim(),
      owner: document.getElementById('d-owner').value.trim(),
      description: document.getElementById('d-desc').value.trim(),
    };
    if (!body.name || !body.source) return toast('名称与来源必填', 'err');
    try { await api('/api/datasets', { method: 'POST', body }); close(); toast('已登记', 'ok'); await renderDatasets(); } catch (e) { toast(e.message, 'err'); }
  };
}

function uploadModal(dsId) {
  const close = modal({
    title: '上传数据文件',
    body: `<p class="sub">支持 .csv 或包含多个 CSV 的 .zip。首行为表头；自由文本列如「出院小结」「病程记录」建议使用中文列名。</p>
      <input type="file" id="up-file" accept=".csv,.zip" multiple>
      <div id="up-list" class="small muted" style="margin-top:10px"></div>`,
    foot: `<button data-close>取消</button><button class="primary" id="up-ok">上传</button>`,
  });
  document.getElementById('up-ok').onclick = async () => {
    const files = document.getElementById('up-file').files;
    if (!files.length) return toast('请选择文件', 'err');
    const fd = new FormData();
    for (const f of files) fd.append('files', f, f.name);
    try {
      const r = await api('/api/datasets/' + dsId + '/upload', { method: 'POST', body: fd });
      close(); toast(`已上传 ${r.files} 个文件 / ${r.rows} 行`, 'ok');
      await renderDatasets();
    } catch (e) { toast(e.message, 'err'); }
  };
}

async function previewModal(dsId) {
  const info = await api('/api/datasets/' + dsId);
  if (!info.files.length) return toast('该数据集还没有文件', 'err');
  const f = info.files[0];
  const close = modal({
    title: `数据预览 · ${f.table_name}`,
    body: `<div class="row" style="margin-bottom:10px">
      <select id="pv-file">${info.files.map((x, i) => `<option value="${x.id}" ${i === 0 ? 'selected' : ''}>${esc(x.table_name)} (${x.row_count} 行)</option>`).join('')}</select>
      <input id="pv-scan" placeholder="搜索内容…" style="flex:1">
    </div><div id="pv-body"></div>`,
  });
  const load = async () => {
    const fid = document.getElementById('pv-file').value;
    const scan = document.getElementById('pv-scan').value;
    const r = await api(`/api/datasets/${dsId}/preview?file=${encodeURIComponent(fid)}&limit=30&scan=${encodeURIComponent(scan)}`);
    document.getElementById('pv-body').innerHTML = `<div class="tbl-wrap"><table><thead><tr>${r.file.headers.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead>
      <tbody>${r.rows.map((row) => `<tr>${row.map((cell) => `<td class="prewrap" style="max-width:340px">${esc(cell)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>
      <div class="tiny muted" style="margin-top:6px">显示 ${r.rows.length} / ${r.file.row_count} 行</div>`;
  };
  document.getElementById('pv-file').onchange = load;
  document.getElementById('pv-scan').oninput = debounce(load, 300);
  await load();
  return close;
}

function projectModal() {
  const close = modal({
    title: '新建课题组',
    body: `<div class="grid c2">
      <label class="f">课题名称 *<input id="p-name" placeholder="如：糖尿病并发症随访研究"></label>
      <label class="f">课题组 *<input id="p-group" placeholder="如：内分泌科课题组"></label>
      <label class="f">联系人<input id="p-contact"></label>
      <label class="f">说明<input id="p-desc"></label>
    </div>`,
    foot: `<button data-close>取消</button><button class="primary" id="p-ok">创建</button>`,
  });
  document.getElementById('p-ok').onclick = async () => {
    const body = {
      name: document.getElementById('p-name').value.trim(),
      group_name: document.getElementById('p-group').value.trim(),
      contact: document.getElementById('p-contact').value.trim(),
      description: document.getElementById('p-desc').value.trim(),
    };
    if (!body.name || !body.group_name) return toast('名称与课题组必填', 'err');
    try { await api('/api/projects', { method: 'POST', body }); close(); toast('已创建', 'ok'); await renderDatasets(); } catch (e) { toast(e.message, 'err'); }
  };
}

function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

// export helpers for other sections
window.__mm = { api, toast, esc, pct, num, modal, confirmBox, el, statusChip, PASS, debounce, copyText };

// ============================================================
// ② 字段识别
// ============================================================

async function ensureDatasetLoaded() {
  await loadDatasets();
  if (!S.currentDataset && S.datasets[0]) S.currentDataset = S.datasets[0].id;
  if (!S.currentDataset) return false;
  return true;
}

function datasetBanner() {
  const d = S.datasets.find((x) => x.id === S.currentDataset);
  if (!d) return '';
  return `<div class="banner info" style="justify-content:space-between">
    <span>当前数据集：<strong>${esc(d.name)}</strong> · ${d.row_count} 行 · ${statusChip(d.status)}</span>
    <span class="row" style="gap:8px">
      <label class="tiny muted">切换数据集</label>
      <span id="ds-switch-slot"></span>
    </span>
  </div>`;
}

function mountDatasetSwitch() {
  const slot = document.getElementById('ds-switch-slot');
  if (!slot) return;
  slot.appendChild(datasetPicker(S.currentDataset, (id) => { S.currentDataset = id; navigate(); }));
}

async function renderFields() {
  if (!(await ensureDatasetLoaded())) {
    document.getElementById('content').innerHTML = '<div class="empty"><div class="big">🗂</div>请先在「数据集登记」创建或生成一个数据集</div>';
    return;
  }
  document.getElementById('head-actions').innerHTML = `
    <button id="run-detect" class="primary">运行字段识别</button>
    <button id="eval-btn">检出率 / 误报率</button>`;
  document.getElementById('run-detect').onclick = async () => {
    try {
      toast('正在识别字段…');
      const r = await api(`/api/datasets/${S.currentDataset}/detect`, { method: 'POST' });
      toast(`识别完成：${r.fields} 字段，直接标识 ${r.direct}，自由文本 ${r.free_text}`, 'ok');
      await renderFields();
    } catch (e) { toast(e.message, 'err'); }
  };
  document.getElementById('eval-btn').onclick = showDetectionEval;

  const [dets, linkage, entities, dsInfo] = await Promise.all([
    api(`/api/datasets/${S.currentDataset}/detections`),
    api(`/api/datasets/${S.currentDataset}/linkage`).catch(() => null),
    api(`/api/datasets/${S.currentDataset}/entities`).catch(() => null),
    api(`/api/datasets/${S.currentDataset}`),
  ]);
  S.fields = dets.detections;
  const c = document.getElementById('content');
  if (!S.fields.length) {
    c.innerHTML = datasetBanner() + `<div class="empty"><div class="big">🔍</div>
      <p>还没有识别结果。点击右上角「运行字段识别」自动识别姓名、身份证、手机、住址、病案号等字段。</p></div>`;
    mountDatasetSwitch();
    return;
  }
  const groups = {};
  S.fields.forEach((f) => (groups[f.table_name] = groups[f.table_name] || []).push(f));
  const direct = S.fields.filter((f) => ['name', 'id_card', 'phone', 'address', 'mrn'].includes(f.detected_type)).length;
  const ft = S.fields.filter((f) => f.detected_type === 'free_text').length;

  c.innerHTML = datasetBanner() + `
    <div class="grid c4">
      <div class="stat"><div class="k">识别字段</div><div class="v">${S.fields.length}</div></div>
      <div class="stat"><div class="k">直接标识字段</div><div class="v" style="color:#ffb6b3">${direct}</div></div>
      <div class="stat"><div class="k">自由文本字段</div><div class="v" style="color:#ffdf8a">${ft}</div></div>
      <div class="stat"><div class="k">跨表关联患者</div><div class="v">${linkage?.linked_across_tables ?? '—'}</div><div class="e">共 ${linkage?.patients ?? '—'} 位患者</div></div>
    </div>
    <div class="card">
      <h2>字段识别结果</h2>
      <p class="sub">置信度低于阈值的字段建议人工复核；修改类型会记录审计。</p>
      <div class="tabs" id="field-tabs">
        <button class="active" data-t="all">全部</button>
        <button data-t="direct">直接标识</button>
        <button data-t="text">自由文本</button>
        <button data-t="quasi">准标识</button>
      </div>
      <div id="field-body"></div>
    </div>
    <div class="grid c2">
      <div class="card">
        <h2>跨表实体关联</h2>
        <p class="sub">${esc(linkage?.strategy || '')}</p>
        <table>
          <tr><td>识别患者数</td><td class="right mono">${linkage?.patients ?? '—'}</td></tr>
          <tr><td>跨表出现（≥2 表）的患者</td><td class="right mono">${linkage?.linked_across_tables ?? '—'}</td></tr>
          <tr><td>唯一身份证号</td><td class="right mono">${linkage?.unique_id_cards ?? '—'}</td></tr>
          <tr><td>唯一病案号</td><td class="right mono">${linkage?.unique_mrns ?? '—'}</td></tr>
          <tr><td>唯一姓名+出生日期</td><td class="right mono">${linkage?.unique_name_birthdates ?? '—'}</td></tr>
        </table>
      </div>
      <div class="card">
        <h2>自由文本标识分布</h2>
        <p class="sub">来自文本扫描的候选标识（未脱敏原文）。</p>
        ${entities && Object.keys(entities.by_type || {}).length ? `<table>${Object.entries(entities.by_type)
          .sort((a, b) => b[1] - a[1])
          .map(([k, v]) => `<tr><td>${esc(k)}</td><td class="right mono">${v}</td></tr>`).join('')}</table>` : '<div class="empty small">暂无自由文本字段或未检出标识</div>'}
      </div>
    </div>`;
  mountDatasetSwitch();

  const renderBody = (filter) => {
    let rows = S.fields;
    if (filter === 'direct') rows = rows.filter((f) => ['name', 'id_card', 'phone', 'address', 'mrn'].includes(f.detected_type));
    else if (filter === 'text') rows = rows.filter((f) => f.detected_type === 'free_text');
    else if (filter === 'quasi') rows = rows.filter((f) => ['age', 'postcode', 'diagnosis', 'gender', 'birth_date', 'date'].includes(f.detected_type));
    const byTable = {};
    rows.forEach((f) => (byTable[f.table_name] = byTable[f.table_name] || []).push(f));
    document.getElementById('field-body').innerHTML = Object.keys(byTable).length
      ? Object.entries(byTable).map(([table, fs]) => `
        <h3>${esc(table)}</h3>
        <div class="tbl-wrap"><table>
          <thead><tr><th>字段</th><th>识别类型</th><th>置信度</th><th>依据</th><th>样例</th><th>操作</th></tr></thead>
          <tbody>${fs.map((f) => `<tr>
            <td><strong>${esc(f.column_name)}</strong></td>
            <td><span class="chip ${DIRECT_TYPES.has(f.detected_type) ? 'bad' : f.detected_type === 'free_text' ? 'warn' : 'gray'}">${esc(f.type_label)}</span></td>
            <td>${confBar(f.confidence)}</td>
            <td class="tiny muted prewrap">${esc(f.evidence)}</td>
            <td class="tiny mono prewrap">${esc(f.sample || '—')}</td>
            <td><button class="sm" data-edit="${f.id}">校正</button></td>
          </tr>`).join('')}</tbody>
        </table></div>`).join('')
      : '<div class="empty small">该分类下没有字段</div>';
    document.querySelectorAll('[data-edit]').forEach((b) => (b.onclick = () => editField(b.dataset.edit)));
  };
  renderBody('all');
  document.querySelectorAll('#field-tabs button').forEach((b) => {
    b.onclick = () => {
      document.querySelectorAll('#field-tabs button').forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
      renderBody(b.dataset.t);
    };
  });
}

const DIRECT_TYPES = new Set(['name', 'id_card', 'phone', 'address', 'mrn']);
const FIELD_TYPES = [
  ['name', '姓名'], ['id_card', '身份证号'], ['phone', '手机号'], ['address', '住址'],
  ['mrn', '病案号'], ['postcode', '邮编'], ['birth_date', '出生日期'], ['date', '日期'],
  ['age', '年龄'], ['gender', '性别'], ['diagnosis', '诊断'], ['free_text', '自由文本'],
  ['numeric', '数值'], ['categorical', '分类'], ['unknown', '未知'],
];

function confBar(v) {
  const p = Math.round(v * 100);
  const col = v >= 0.85 ? '#2ea043' : v >= 0.65 ? '#d29922' : '#f85149';
  return `<div class="row" style="gap:6px"><div class="progress" style="width:70px"><div style="width:${p}%;background:${col}"></div></div><span class="tiny mono">${p}%</span></div>`;
}

function editField(id) {
  const f = S.fields.find((x) => x.id === id);
  const close = modal({
    title: `校正字段 · ${f.table_name} / ${f.column_name}`,
    body: `<p class="sub">当前识别为「${esc(f.type_label)}」，置信度 ${(f.confidence * 100).toFixed(0)}%。</p>
      <div class="grid c2">
        <label class="f">字段类型<select id="ef-type">${FIELD_TYPES.map(([v, l]) => `<option value="${v}" ${v === f.detected_type ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
        <label class="f">样例<input value="${esc(f.sample || '')}" disabled></label>
      </div>
      <div class="hint" style="margin-top:12px">人工校正后该字段标记为「人工」，审计记录会保留调整前后的类型。</div>`,
    foot: `<button data-close>取消</button><button class="primary" id="ef-ok">保存</button>`,
  });
  document.getElementById('ef-ok').onclick = async () => {
    const t = document.getElementById('ef-type').value;
    try {
      await api(`/api/datasets/${S.currentDataset}/detections/${id}`, { method: 'PUT', body: { detected_type: t, confirmed: true } });
      close(); toast('已保存', 'ok'); await renderFields();
    } catch (e) { toast(e.message, 'err'); }
  };
}

async function showDetectionEval() {
  const r = await api(`/api/datasets/${S.currentDataset}/detection-eval`);
  const ev = r.detection_eval;
  const ce = r.column_eval;
  if (!ev) {
    return modal({ title: '检出率 / 误报率', body: '<p class="sub">该数据集没有埋点真值。只有通过「测试数据与检出率」页生成的合成数据才带真值，可用于计算检出率与误报率。</p>' });
  }
  const t = ev.totals;
  const body = `
    <div class="kpi-row">
      <div class="kpi"><div class="k">文本标识真值</div><div class="v">${t.truth}</div></div>
      <div class="kpi"><div class="k">检出</div><div class="v">${t.detected}</div></div>
      <div class="kpi"><div class="k">检出率(召回)</div><div class="v" style="color:#56d364">${pct(t.recall)}</div></div>
      <div class="kpi"><div class="k">准确率(精确)</div><div class="v" style="color:#79c0ff">${pct(t.precision)}</div></div>
      <div class="kpi"><div class="k">误报率</div><div class="v" style="color:#ffb6b3">${pct(t.fpr)}</div></div>
    </div>
    <h3>分类型指标</h3>
    <div class="tbl-wrap"><table>
      <thead><tr><th>类型</th><th>真值</th><th>检出</th><th>TP</th><th>FP</th><th>FN</th><th>检出率</th><th>误报率</th></tr></thead>
      <tbody>${ev.per_type.map((x) => `<tr>
        <td>${esc(x.pii_type)}</td><td>${x.truth}</td><td>${x.detected}</td>
        <td>${x.tp}</td><td>${x.fp}</td><td>${x.fn_}</td>
        <td>${pct(x.recall)}</td><td>${pct(x.fpr)}</td></tr>`).join('')}</tbody>
    </table></div>
    ${ev.unmatched.length ? `<h3>漏检样例（${ev.unmatched.length}）</h3><div class="code">${ev.unmatched.slice(0, 20).map((u) => esc(u.pii_type + ' | ' + u.text + ' | ' + u.column)).join('\n')}</div>` : ''}
    ${ev.false_positives?.length ? `<h3>误报样例（${ev.false_positives.length}）</h3><div class="code">${ev.false_positives.slice(0, 20).map((u) => esc(u.pii_type + ' | ' + u.text)).join('\n')}</div>` : ''}
    ${ce ? `<h3>结构化字段识别准确率：${pct(ce.accuracy)}（${ce.correct}/${ce.columns}）</h3>
      ${ce.mistakes.length ? `<div class="code">${ce.mistakes.map((m) => esc(`${m.table}.${m.column}: 期望 ${m.expected}, 实际 ${m.actual}`)).join('\n')}</div>` : '<p class="small pass">全部字段类型识别正确</p>'}` : ''}
    <h3>检测规则命中分布</h3>
    <div class="row">${Object.entries(ev.by_rule).map(([k, v]) => `<span class="chip">${esc(k)} · ${v}</span>`).join('')}</div>`;
  modal({ title: '检出率 / 误报率报告', body });
}

// ============================================================
// ③ 脱敏策略
// ============================================================

const DEFAULT_POLICY = {
  version: 1, notes: '',
  direct: { name: 'pseudonym', id_card: 'pseudonym', phone: 'mask', address: 'generalize', mrn: 'pseudonym', phone_keep_last: 4, address_level: 'district', pseudonym_prefix: 'P' },
  free_text: { enabled: true, name: 'pseudonym', id_card: 'mask', phone: 'mask', address: 'generalize', mrn: 'pseudonym', date: 'shift', birth_date: 'generalize', postcode: 'mask', address_level: 'district' },
  dates: { action: 'shift', min_days: -365, max_days: -30, granularity: 'month' },
  quasi: { age_width: 5, postcode_keep_prefix: 4, diagnosis_level: 'icd3', gender: 'keep', birth_date: 'year' },
  k_anonymity: { k: 5, max_age_width: 20, min_postcode_prefix: 2, auto_escalate: true },
  risk: { max_reid_risk: 0.2, max_prosecution_risk: 0.2, require_no_residual_pii: true },
  quality: { max_relative_deviation: 0.25 },
};

async function renderPolicy() {
  if (!(await ensureDatasetLoaded())) {
    document.getElementById('content').innerHTML = '<div class="empty"><div class="big">🗂</div>请先创建数据集</div>';
    return;
  }
  const r = await api(`/api/datasets/${S.currentDataset}/policy`);
  S.policy = r.policy;
  S.policyDraft = deepCopy(S.policy.config || DEFAULT_POLICY);
  const c = document.getElementById('content');
  c.innerHTML = datasetBanner() + `
    <div class="card">
      <div class="row" style="justify-content:space-between;margin-bottom:8px">
        <div><h2>策略配置 <span class="chip blue">v${S.policy.version || 0}</span></h2>
          <p class="sub">${S.policy.id ? '当前策略「' + esc(S.policy.name) + '」' : '尚未保存策略，以下为默认值'}</p></div>
        <div class="row"><button class="ghost sm" id="p-reset">恢复默认</button><button class="primary" id="p-save">保存为新版本</button></div>
      </div>
      <div id="policy-form"></div>
    </div>
    <div class="card">
      <h2>脱敏效果预览</h2>
      <p class="sub">按当前配置在数据集前 800 行上试跑，不落库、不发包，仅用于确认规则。</p>
      <div class="row" style="margin-bottom:12px">
        <label class="f">课题组<select id="pv-project">${S.projects.map((p) => `<option value="${p.id}">${esc(p.group_name)} · ${esc(p.name)}</option>`).join('')}</select></label>
        <label class="f" style="max-width:120px">k 值<input id="pv-k" type="number" value="${S.policyDraft.k_anonymity.k}" min="2" max="50"></label>
        <div class="spacer"></div>
        <button class="primary" id="pv-run" style="align-self:flex-end">试跑预览</button>
      </div>
      <div id="pv-result" class="muted small">点击「试跑预览」查看脱敏前后对比与风险摘要</div>
    </div>`;
  mountDatasetSwitch();
  renderPolicyForm();
  document.getElementById('p-reset').onclick = () => { S.policyDraft = deepCopy(DEFAULT_POLICY); renderPolicyForm(); toast('已恢复默认配置（未保存）'); };
  document.getElementById('p-save').onclick = savePolicy;
  document.getElementById('pv-run').onclick = runPreview;
}

function deepCopy(o) { return JSON.parse(JSON.stringify(o)); }

function fieldSelect(id, value, options) {
  return `<select id="${id}">${options.map(([v, l]) => `<option value="${v}" ${v === value ? 'selected' : ''}>${l}</option>`).join('')}</select>`;
}
function fieldNum(id, value, min, max, step = 1) {
  return `<input id="${id}" type="number" value="${value}" min="${min}" max="${max}" step="${step}">`;
}

const ACTION_OPTS = [['pseudonym', '假名化（推荐）'], ['mask', '遮盖'], ['hash', '哈希编码'], ['generalize', '泛化'], ['suppress', '删除'], ['keep', '保留']];
const TEXT_ACTION_OPTS = [['pseudonym', '假名化'], ['mask', '遮盖'], ['hash', '哈希'], ['generalize', '泛化'], ['suppress', '删除'], ['keep', '保留']];

function renderPolicyForm() {
  const p = S.policyDraft;
  document.getElementById('policy-form').innerHTML = `
    <h3>A · 直接标识字段</h3>
    <div class="grid c3">
      <label class="f">姓名处理${fieldSelect('d-name', p.direct.name, ACTION_OPTS)}</label>
      <label class="f">身份证号${fieldSelect('d-id', p.direct.id_card, ACTION_OPTS)}</label>
      <label class="f">手机号${fieldSelect('d-phone', p.direct.phone, ACTION_OPTS)}</label>
      <label class="f">住址${fieldSelect('d-addr', p.direct.address, ACTION_OPTS)}</label>
      <label class="f">病案号${fieldSelect('d-mrn', p.direct.mrn, ACTION_OPTS)}</label>
      <label class="f">手机号保留末几位${fieldNum('d-keep', p.direct.phone_keep_last, 0, 8)}</label>
      <label class="f">住址泛化层级${fieldSelect('d-level', p.direct.address_level, [['province', '保留省/直辖市'], ['city', '保留到市'], ['district', '保留到区/县']])}</label>
      <label class="f">假名前缀<input id="d-prefix" value="${esc(p.direct.pseudonym_prefix)}" maxlength="4"></label>
    </div>
    <h3>B · 自由文本标识</h3>
    <div class="grid c4">
      <label class="f">启用文本脱敏${fieldSelect('f-enabled', p.free_text.enabled ? 'y' : 'n', [['y', '启用'], ['n', '关闭']])}</label>
      <label class="f">姓名${fieldSelect('f-name', p.free_text.name, TEXT_ACTION_OPTS)}</label>
      <label class="f">身份证号${fieldSelect('f-id', p.free_text.id_card, TEXT_ACTION_OPTS)}</label>
      <label class="f">手机号${fieldSelect('f-phone', p.free_text.phone, TEXT_ACTION_OPTS)}</label>
      <label class="f">住址${fieldSelect('f-addr', p.free_text.address, TEXT_ACTION_OPTS)}</label>
      <label class="f">病案号${fieldSelect('f-mrn', p.free_text.mrn, TEXT_ACTION_OPTS)}</label>
      <label class="f">日期${fieldSelect('f-date', p.free_text.date, [['shift', '同患者平移'], ['generalize', '泛化到月'], ['suppress', '删除']])}</label>
      <label class="f">邮编${fieldSelect('f-pc', p.free_text.postcode, TEXT_ACTION_OPTS)}</label>
    </div>
    <h3>C · 日期平移</h3>
    <div class="grid c4">
      <label class="f">日期处理方式${fieldSelect('dt-action', p.dates.action, [['shift', '按患者整体平移'], ['generalize', '泛化到月'], ['suppress', '删除']])}</label>
      <label class="f">最少偏移天数${fieldNum('dt-min', p.dates.min_days, -3650, 0)}</label>
      <label class="f">最多偏移天数${fieldNum('dt-max', p.dates.max_days, -3650, 3650)}</label>
      <label class="f">泛化粒度${fieldSelect('dt-gran', p.dates.granularity, [['month', '到月'], ['year', '到年']])}</label>
    </div>
    <div class="hint">同一患者所有表的日期使用同一个偏移量，因此住院天数、两次就诊间隔、用药间隔均保持不变。</div>
    <h3>D · 准标识符泛化与 k 匿名</h3>
    <div class="grid c4">
      <label class="f">年龄分段宽度（岁）${fieldNum('q-age', p.quasi.age_width, 1, 20)}</label>
      <label class="f">邮编保留前缀位数${fieldNum('q-pc', p.quasi.postcode_keep_prefix, 0, 6)}</label>
      <label class="f">诊断泛化层级${fieldSelect('q-dx', p.quasi.diagnosis_level, [['icd3', 'ICD 三位码'], ['icd2', '按系统'], ['chapter', '按章']])}</label>
      <label class="f">出生日期${fieldSelect('q-birth', p.quasi.birth_date, [['year', '仅保留年份'], ['shift', '同日期平移']])}</label>
      <label class="f">目标 k 值 *${fieldNum('k-value', p.k_anonymity.k, 2, 50)}</label>
      <label class="f">年龄最大分段宽度${fieldNum('k-maxage', p.k_anonymity.max_age_width, 5, 20)}</label>
      <label class="f">邮编最小前缀位数${fieldNum('k-minpc', p.k_anonymity.min_postcode_prefix, 0, 6)}</label>
      <label class="f">自动升级泛化${fieldSelect('k-auto', p.k_anonymity.auto_escalate ? 'y' : 'n', [['y', '是（推荐）'], ['n', '否']])}</label>
    </div>
    <div class="hint">若按当前泛化仍达不到目标 k，系统会自动加宽年龄分段、缩短邮编前缀、上移诊断泛化层级，直到满足 k 或达到上限；仍不达标则阻止发布。</div>
    <h3>E · 风险与质量阈值</h3>
    <div class="grid c4">
      <label class="f">最大再识别风险${fieldNum('r-reid', p.risk.max_reid_risk, 0, 1, 0.01)}</label>
      <label class="f">最大起诉风险${fieldNum('r-pros', p.risk.max_prosecution_risk, 0, 1, 0.01)}</label>
      <label class="f">禁止残留直接标识${fieldSelect('r-res', p.risk.require_no_residual_pii ? 'y' : 'n', [['y', '是'], ['n', '否']])}</label>
      <label class="f">最大统计量相对偏差${fieldNum('r-dev', p.quality.max_relative_deviation, 0, 1, 0.01)}</label>
    </div>`;
  bindPolicyInputs();
}

function bindPolicyInputs() {
  const p = S.policyDraft;
  const get = (id) => document.getElementById(id);
  const on = (id, fn) => { const e = get(id); if (e) e.oninput = e.onchange = fn; };
  on('d-name', (e) => p.direct.name = e.target.value);
  on('d-id', (e) => p.direct.id_card = e.target.value);
  on('d-phone', (e) => p.direct.phone = e.target.value);
  on('d-addr', (e) => p.direct.address = e.target.value);
  on('d-mrn', (e) => p.direct.mrn = e.target.value);
  on('d-keep', (e) => p.direct.phone_keep_last = +e.target.value);
  on('d-level', (e) => p.direct.address_level = e.target.value);
  on('d-prefix', (e) => p.direct.pseudonym_prefix = e.target.value);
  on('f-enabled', (e) => p.free_text.enabled = e.target.value === 'y');
  on('f-name', (e) => p.free_text.name = e.target.value);
  on('f-id', (e) => p.free_text.id_card = e.target.value);
  on('f-phone', (e) => p.free_text.phone = e.target.value);
  on('f-addr', (e) => p.free_text.address = e.target.value);
  on('f-mrn', (e) => p.free_text.mrn = e.target.value);
  on('f-date', (e) => p.free_text.date = e.target.value);
  on('f-pc', (e) => p.free_text.postcode = e.target.value);
  on('dt-action', (e) => p.dates.action = e.target.value);
  on('dt-min', (e) => p.dates.min_days = +e.target.value);
  on('dt-max', (e) => p.dates.max_days = +e.target.value);
  on('dt-gran', (e) => p.dates.granularity = e.target.value);
  on('q-age', (e) => p.quasi.age_width = +e.target.value);
  on('q-pc', (e) => p.quasi.postcode_keep_prefix = +e.target.value);
  on('q-dx', (e) => p.quasi.diagnosis_level = e.target.value);
  on('q-birth', (e) => p.quasi.birth_date = e.target.value);
  on('k-value', (e) => p.k_anonymity.k = +e.target.value);
  on('k-maxage', (e) => p.k_anonymity.max_age_width = +e.target.value);
  on('k-minpc', (e) => p.k_anonymity.min_postcode_prefix = +e.target.value);
  on('k-auto', (e) => p.k_anonymity.auto_escalate = e.target.value === 'y');
  on('r-reid', (e) => p.risk.max_reid_risk = +e.target.value);
  on('r-pros', (e) => p.risk.max_prosecution_risk = +e.target.value);
  on('r-res', (e) => p.risk.require_no_residual_pii = e.target.value === 'y');
  on('r-dev', (e) => p.quality.max_relative_deviation = +e.target.value);
}

async function savePolicy() {
  const name = `科研脱敏策略 v${(S.policy.version || 0) + 1}`;
  try {
    const r = await api(`/api/datasets/${S.currentDataset}/policy`, { method: 'PUT', body: { name, config: S.policyDraft } });
    toast(`已保存策略 v${r.version}`, 'ok');
    await renderPolicy();
  } catch (e) { toast(e.message, 'err'); }
}

async function runPreview() {
  const project = document.getElementById('pv-project')?.value || 'preview';
  const k = document.getElementById('pv-k')?.value || 5;
  // persist draft first so the server-side transform preview uses it
  try {
    await api(`/api/datasets/${S.currentDataset}/policy`, { method: 'PUT', body: { name: `科研脱敏策略 v${(S.policy.version || 0) + 1}（预览）`, config: S.policyDraft } });
    // reload policy so version bumps are consistent
    const pr = await api(`/api/datasets/${S.currentDataset}/policy`);
    S.policy = pr.policy;
  } catch (e) { toast('保存策略失败：' + e.message, 'err'); return; }
  const box = document.getElementById('pv-result');
  box.innerHTML = '<div class="muted small">试跑中…</div>';
  try {
    const r = await api(`/api/datasets/${S.currentDataset}/transform-preview?project=${project}&k=${k}&limit=8`);
    box.innerHTML = previewResultHtml(r);
  } catch (e) {
    box.innerHTML = `<div class="banner bad">${esc(e.message)}</div>`;
  }
}

function previewResultHtml(r) {
  const risk = r.risk;
  const q = r.quality;
  S._lastPreview = r;
  const tabId = 'pv-tabs-' + Math.random().toString(36).slice(2);
  const html = `
    <div class="kpi-row">
      <div class="kpi"><div class="k">最小等价类</div><div class="v ${risk.min_class_size >= risk.k_target ? 'pass' : 'fail'}">${risk.min_class_size}</div><div class="tiny muted">目标 k=${risk.k_target}</div></div>
      <div class="kpi"><div class="k">再识别风险</div><div class="v">${(risk.max_reid_risk * 100).toFixed(1)}%</div></div>
      <div class="kpi"><div class="k">残留直接标识</div><div class="v">${risk.high_confidence_residual}</div></div>
      <div class="kpi"><div class="k">抑制行数</div><div class="v">${risk.suppressed_rows}</div></div>
      <div class="kpi"><div class="k">住院天数偏差</div><div class="v">${q.los_rel_dev == null ? '—' : pct(q.los_rel_dev)}</div></div>
      <div class="kpi"><div class="k">用药间隔保持</div><div class="v ${q.interval_preserved ? 'pass' : 'fail'}">${q.interval_preserved ? '是' : '否'}</div></div>
    </div>
    <div class="criteria" style="margin:4px 0 14px">${risk.criteria.map((x) => `<div class="crit ${x.passed ? 'pass' : 'fail'}"><div class="name">${x.passed ? '✓' : '✗'} ${esc(x.name)}</div><div class="detail">${esc(x.detail)}</div></div>`).join('')}</div>
    <div class="tabs" id="${tabId}">${r.samples.map((t, i) => `<button class="${i === 0 ? 'active' : ''}" data-i="${i}" data-tab="${tabId}">${esc(t.table)}</button>`).join('')}</div>
    <div id="${tabId}-body"></div>`;
  setTimeout(() => {
    const tabs = document.getElementById(tabId);
    if (!tabs) return;
    tabs.querySelectorAll('button').forEach((b) => {
      b.onclick = () => {
        tabs.querySelectorAll('button').forEach((x) => x.classList.remove('active'));
        b.classList.add('active');
        renderPreviewTable(r, +b.dataset.i, `${tabId}-body`);
      };
    });
    renderPreviewTable(r, 0, `${tabId}-body`);
  }, 0);
  return html;
}

function renderPreviewTable(r, idx, mountId) {
  const t = r.samples[idx];
  const rounds = (r.decisions || []).filter((d) => d.table === t.table);
  const decisions = {};
  rounds.forEach((d) => (decisions[d.column] = d));
  document.getElementById(mountId).innerHTML = `
    <div class="tbl-wrap"><table>
      <thead><tr>${t.headers.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead>
      <tbody>${t.rows.map((row) => `<tr>${row.map((cell, ci) => {
        const dec = decisions[t.headers[ci]];
        const intro = dec ? `<div class="tiny"><span class="chip ${dec.kind === '自由文本' ? 'warn' : 'blue'}">${esc(dec.collabel || dec.kind)}</span></div>` : '';
        return `<td class="prewrap" style="max-width:360px">${intro}${esc(cell)}</td>`;
      }).join('')}</tr>`).join('')}</tbody>
    </table></div>
    <div class="row" style="margin-top:10px;gap:8px">
      ${Object.values(decisions).map((d) => `<span class="chip">${esc(d.column)}：${esc(d.action)} · ${esc(d.detail)}</span>`).join('')}
    </div>`;
}

// ============================================================
// ④ 风险评估
// ============================================================

async function renderRisk() {
  if (!(await ensureDatasetLoaded())) {
    document.getElementById('content').innerHTML = '<div class="empty"><div class="big">🗂</div>请先创建数据集</div>';
    return;
  }
  await loadProjects();
  const policy = await api(`/api/datasets/${S.currentDataset}/policy`);
  S.policy = policy.policy;
  const c = document.getElementById('content');
  c.innerHTML = datasetBanner() + `
    <div class="card">
      <h2>发起风险评估</h2>
      <p class="sub">按当前已保存策略（v${policy.policy.version}）对全量数据试跑，评估 k 匿名、再识别风险、残留标识与统计量偏差。此操作不生成发布包。</p>
      <div class="row">
        <label class="f">课题组<select id="risk-project">${S.projects.map((p) => `<option value="${p.id}">${esc(p.group_name)} · ${esc(p.name)}</option>`).join('')}</select></label>
        <label class="f" style="max-width:120px">k 值<input id="risk-k" type="number" value="${policy.policy.config.k_anonymity.k}" min="2" max="50"></label>
        <div class="spacer"></div>
        <button class="primary" id="risk-run" style="align-self:flex-end">运行评估</button>
      </div>
    </div>
    <div id="risk-result"></div>`;
  mountDatasetSwitch();
  document.getElementById('risk-run').onclick = runRisk;
  // auto-run for convenience
  runRisk();
}

async function runRisk() {
  const project = document.getElementById('risk-project').value;
  const k = document.getElementById('risk-k').value;
  const box = document.getElementById('risk-result');
  box.innerHTML = '<div class="card"><div class="muted">评估中，请稍候…</div></div>';
  try {
    const r = await api(`/api/datasets/${S.currentDataset}/transform-preview?project=${project}&k=${k}&limit=5`);
    box.innerHTML = riskReportHtml(r);
  } catch (e) {
    box.innerHTML = `<div class="card"><div class="banner bad">${esc(e.message)}</div></div>`;
  }
}

function riskReportHtml(r) {
  const risk = r.risk, q = r.quality;
  const pass = risk.passed;
  const crit = risk.criteria || [];
  const numeric = (q.numeric || []);
  return `
    <div class="banner ${pass ? 'ok' : 'bad'}">
      <strong>${pass ? '✓ 风险评估通过，可提交审批' : '✗ 风险评估未通过，禁止发布与导出'}</strong>
      <span class="small" style="margin-left:auto">k 目标 ${risk.k_target} · 实际最小等价类 ${risk.min_class_size} · 等价类 ${risk.equivalence_classes} 个</span>
    </div>
    <div class="grid c2">
      <div class="card">
        <h2>合规判定</h2>
        <div class="criteria">${crit.map((x) => `
          <div class="crit ${x.passed ? 'pass' : 'fail'}">
            <div class="name">${x.passed ? '✓' : '✗'} ${esc(x.name)}</div>
            <div class="detail">${esc(x.detail)}</div>
          </div>`).join('')}</div>
      </div>
      <div class="card">
        <h2>风险指标</h2>
        <div class="kpi-row">
          <div class="kpi"><div class="k">最小等价类</div><div class="v">${risk.min_class_size}</div></div>
          <div class="kpi"><div class="k">再识别风险</div><div class="v">${(risk.max_reid_risk * 100).toFixed(1)}%</div></div>
          <div class="kpi"><div class="k">起诉风险</div><div class="v">${(risk.prosecution_risk * 100).toFixed(1)}%</div></div>
          <div class="kpi"><div class="k">抑制行 / 患者</div><div class="v">${risk.suppressed_rows} / ${risk.patients_suppressed || 0}</div></div>
          <div class="kpi"><div class="k">残留高置信标识</div><div class="v ${risk.high_confidence_residual ? 'fail' : 'pass'}">${risk.high_confidence_residual}</div></div>
          <div class="kpi"><div class="k">准标识列</div><div class="v" style="font-size:13px">${(risk.qi_columns || []).map(esc).join('、') || '—'}</div></div>
        </div>
        <h3>泛化后取值示例</h3>
        <p class="sub">准标识符经过泛化后进入等价类：</p>
        <div class="row">${(risk.qi_after || []).map((q2) => `<span class="chip blue">${esc(q2)}</span>`).join('')}</div>
      </div>
    </div>
    <div class="card">
      <h2>关键统计量偏差（脱敏前 → 脱敏后）</h2>
      <p class="sub">数值型字段的均值/中位数/标准差偏差；住院天数与给药间隔属于必须保持的区间量。</p>
      <div class="tbl-wrap"><table>
        <thead><tr><th>表</th><th>字段</th><th>n</th><th>均值 前 → 后</th><th>中位数 前 → 后</th><th>标准差 前 → 后</th><th>均值偏差</th><th>类型</th></tr></thead>
        <tbody>${numeric.map((s) => `<tr>
          <td>${esc(s.table)}</td><td>${esc(s.column)}</td><td class="mono">${s.n_before}→${s.n_after}</td>
          <td class="mono">${num(s.before_mean)} → ${num(s.after_mean)}</td>
          <td class="mono">${num(s.before_median)} → ${num(s.after_median)}</td>
          <td class="mono">${num(s.before_std)} → ${num(s.after_std)}</td>
          <td class="${s.rel_dev_mean > 0.01 ? 'fail' : 'pass'}">${pct(s.rel_dev_mean)}</td>
          <td>${s.is_interval ? '<span class="chip ok">区间量·须保持</span>' : s.quasi ? '<span class="chip warn">准标识泛化</span>' : '<span class="chip gray">数值</span>'}</td>
        </tr>`).join('')}</tbody>
      </table></div>
      <div class="row" style="margin-top:12px;gap:16px">
        <span>住院天数均值：<strong class="mono">${q.los_before_mean == null ? '—' : num(q.los_before_mean)} → ${q.los_after_mean == null ? '—' : num(q.los_after_mean)}</strong></span>
        <span>区间量保持：${q.interval_preserved ? '<span class="chip ok">是</span>' : '<span class="chip bad">否</span>'}</span>
        <span>最大非准标识偏差：<strong class="mono">${pct(q.max_rel_dev)}</strong></span>
      </div>
    </div>
    ${risk.residual_count ? `<div class="card">
      <h2>残留标识扫描 <span class="chip bad">${risk.residual_count} 处</span></h2>
      <p class="sub">脱敏后文本中仍能检出的直接标识（已排除假名与遮盖值）。</p>
      <div class="tbl-wrap"><table><thead><tr><th>表</th><th>字段</th><th>类型</th><th>规则</th><th>片段</th><th>置信度</th></tr></thead>
      <tbody>${risk.residual.slice(0, 50).map((x) => `<tr><td>${esc(x.table)}</td><td>${esc(x.column)}</td><td>${esc(x.pii_type)}</td><td class="mono tiny">${esc(x.rule)}</td><td class="mono prewrap">${esc(x.snippet)}</td><td>${pct(x.confidence)}</td></tr>`).join('')}</tbody></table></div>
    </div>` : '<div class="card"><h2>残留标识扫描</h2><p class="pass">✓ 未检出残留直接标识</p></div>'}
    ${risk.suppressed_rows ? `<div class="card"><h2>抑制说明</h2><p class="small">为保证 k 匿名，系统移除了属于小等价类的 ${risk.patients_suppressed || 0} 位患者共 ${risk.suppressed_rows} 行记录。抑制只影响规模，已在质量报告中单列。</p></div>` : ''}`;
}

// ============================================================
// ⑤ 发布审批
// ============================================================

async function renderApproval() {
  await Promise.all([loadDatasets(), loadProjects()]);
  applyRouteDefaults();
  const rels = await api('/api/releases');
  S.releases = rels.releases;
  const c = document.getElementById('content');
  document.getElementById('head-actions').innerHTML = '<button class="primary" id="new-release">发起发布评估</button>';
  document.getElementById('new-release').onclick = newReleaseModal;

  const pending = S.releases.filter((r) => r.status === 'pending').length;
  const blocked = S.releases.filter((r) => r.status === 'blocked').length;
  const approved = S.releases.filter((r) => r.status === 'approved').length;
  c.innerHTML = datasetBannerForApproval() + `
    <div class="grid c4">
      <div class="stat"><div class="k">待审批</div><div class="v" style="color:#ffdf8a">${pending}</div></div>
      <div class="stat"><div class="k">风险拦截</div><div class="v" style="color:#ffb6b3">${blocked}</div></div>
      <div class="stat"><div class="k">已批准</div><div class="v" style="color:#56d364">${approved}</div></div>
      <div class="stat"><div class="k">全部发布</div><div class="v">${S.releases.length}</div></div>
    </div>
    <div class="card" style="margin-top:16px">
      <h2>发布记录</h2>
      <p class="sub">审批通过后系统生成脱敏发布包（CSV + 清单 + 风险/质量报告），并以哈希链记录全过程。</p>
      ${S.releases.length ? `<div class="tbl-wrap"><table>
        <thead><tr><th>发布编号</th><th>数据集</th><th>课题组</th><th>策略</th><th>k / 最小类</th><th>状态</th><th>创建</th><th>操作</th></tr></thead>
        <tbody>${S.releases.map((r) => `<tr>
          <td class="mono tiny">${esc(r.id)}</td>
          <td>${esc(r.dataset_name)}</td>
          <td>${esc(r.group_name)}<div class="tiny muted">${esc(r.project_name)}</div></td>
          <td class="mono tiny">v${r.policy_version}</td>
          <td>${r.k} / ${r.risk?.min_class_size ?? '—'}</td>
          <td>${statusChip(r.status)}</td>
          <td class="tiny muted">${esc(r.created_at)}<div>${esc(r.created_by)}</div></td>
          <td class="nowrap">
            <button class="sm" data-detail="${r.id}">详情</button>
            ${r.status === 'pending' && r.passed ? `<button class="sm primary" data-approve="${r.id}">批准</button>` : ''}
            ${r.status === 'pending' || r.status === 'blocked' ? `<button class="sm" data-reject="${r.id}">驳回</button>` : ''}
            ${r.status === 'approved' ? `<button class="sm" data-export="${r.id}">导出包</button>` : ''}
            ${r.status !== 'approved' ? `<button class="sm danger" data-del="${r.id}">删除</button>` : ''}
          </td></tr>`).join('')}</tbody></table></div>` : '<div class="empty"><div class="big">📦</div>还没有发布记录</div>'}
    </div>`;
  c.querySelectorAll('[data-detail]').forEach((b) => (b.onclick = () => showRelease(b.dataset.detail)));
  c.querySelectorAll('[data-approve]').forEach((b) => (b.onclick = () => approveRelease(b.dataset.approve)));
  c.querySelectorAll('[data-reject]').forEach((b) => (b.onclick = () => rejectRelease(b.dataset.reject)));
  c.querySelectorAll('[data-export]').forEach((b) => (b.onclick = () => exportRelease(b.dataset.export)));
  c.querySelectorAll('[data-del]').forEach((b) => (b.onclick = () => confirmBox('删除该发布记录？', async () => {
    try { await api('/api/releases/' + b.dataset.del, { method: 'DELETE' }); toast('已删除', 'ok'); await renderApproval(); } catch (e) { toast(e.message, 'err'); }
  }, '删除')));
}

function datasetBannerForApproval() {
  return ''; // approval lists all datasets; selection happens in the modal
}

function applyRouteDefaults() {}

function newReleaseModal() {
  if (!S.datasets.length) return toast('请先创建数据集', 'err');
  if (!S.projects.length) return toast('请先创建课题组', 'err');
  const close = modal({
    title: '发起发布评估',
    body: `<p class="sub">选择数据集与课题组，系统按该数据集当前保存的策略评估风险；只有评估通过才能进入审批。</p>
      <div class="grid c2">
        <label class="f">数据集<select id="nr-ds">${S.datasets.map((d) => `<option value="${d.id}">${esc(d.name)}</option>`).join('')}</select></label>
        <label class="f">课题组<select id="nr-prj">${S.projects.map((p) => `<option value="${p.id}">${esc(p.group_name)} · ${esc(p.name)}</option>`).join('')}</select></label>
        <label class="f">k 值（留空用策略值）<input id="nr-k" type="number" min="2" max="50" placeholder="如 5"></label>
        <label class="f">发起人<input id="nr-by" value="${esc(document.getElementById('actor').value)}"></label>
      </div>
      <div class="hint" style="margin-top:12px">评估不通过会生成一条「风险未通过」记录并写入审计，不能审批或导出。</div>`,
    foot: `<button data-close>取消</button><button class="primary" id="nr-ok">开始评估</button>`,
  });
  document.getElementById('nr-ok').onclick = async () => {
    const body = {
      dataset_id: document.getElementById('nr-ds').value,
      project_id: document.getElementById('nr-prj').value,
      created_by: document.getElementById('nr-by').value || '科研处管理员',
    };
    const kv = document.getElementById('nr-k').value;
    if (kv) body.k = +kv;
    try {
      const r = await api('/api/releases', { method: 'POST', body });
      close();
      toast(r.passed ? '评估通过，进入待审批' : '评估未通过，已阻止发布', r.passed ? 'ok' : 'err');
      await renderApproval();
    } catch (e) { toast(e.message, 'err'); }
  };
}

async function showRelease(id) {
  const r = await api('/api/releases/' + id);
  const rel = r.release;
  const risk = rel.risk || {};
  const q = rel.quality || {};
  const body = `
    <div class="row" style="margin-bottom:10px">${statusChip(rel.status)}
      <span class="small muted">${esc(rel.dataset_name)} → ${esc(rel.group_name)} · 策略 v${rel.policy_version}</span>
      <span class="spacer"></span>${rel.passed ? '<span class="chip ok">评估通过</span>' : '<span class="chip bad">评估未通过</span>'}</div>
    <div class="criteria" style="margin-bottom:14px">${(risk.criteria || []).map((x) => `<div class="crit ${x.passed ? 'pass' : 'fail'}"><div class="name">${x.passed ? '✓' : '✗'} ${esc(x.name)}</div><div class="detail">${esc(x.detail)}</div></div>`).join('')}</div>
    <div class="grid c3">
      <div class="kpi"><div class="k">目标 k</div><div class="v">${rel.k}</div></div>
      <div class="kpi"><div class="k">最小等价类</div><div class="v">${risk.min_class_size ?? '—'}</div></div>
      <div class="kpi"><div class="k">残留标识</div><div class="v">${risk.high_confidence_residual ?? '—'}</div></div>
    </div>
    <h3>策略快照</h3>
    <div class="code">${esc(JSON.stringify(rel.policy_snapshot, null, 2))}</div>
    ${rel.approved_at ? `<h3>审批信息</h3><table>
      <tr><td>审批人</td><td>${esc(rel.approved_by)}</td></tr>
      <tr><td>审批时间</td><td>${esc(rel.approved_at)}</td></tr>
      <tr><td>发布包 SHA-256</td><td class="mono tiny prewrap">${esc(rel.artifact_sha256)}</td></tr>
    </table>` : ''}
    ${rel.rejected_reason ? `<div class="banner bad" style="margin-top:10px">驳回原因：${esc(rel.rejected_reason)}</div>` : ''}
    ${rel.manifest && rel.manifest.files ? `<h3>发布包内容</h3><div class="tbl-wrap"><table>
      <thead><tr><th>文件</th><th>行数</th><th>字节</th><th>SHA-256</th></tr></thead>
      <tbody>${rel.manifest.files.map((f) => `<tr><td class="mono">${esc(f.name)}</td><td>${f.rows}</td><td>${f.bytes}</td><td class="mono tiny">${esc(f.sha256.slice(0, 20))}…</td></tr>`).join('')}</tbody>
    </table></div>` : ''}
    <h3>关联审计（可追溯）</h3>
    <div id="rel-audit" class="small muted">加载中…</div>`;
  modal({ title: '发布详情 · ' + rel.id, body });
  try {
    const a = await api(`/api/audit?release_id=${rel.id}&limit=100`);
    document.getElementById('rel-audit').innerHTML = a.events.length
      ? `<div class="tbl-wrap"><table><thead><tr><th>时间</th><th>操作人</th><th>动作</th><th>详情</th><th>链</th></tr></thead><tbody>${a.events.map((e) => `<tr><td class="tiny">${esc(e.event_time)}</td><td>${esc(e.actor)}</td><td class="mono tiny">${esc(e.action)}</td><td class="tiny">${esc(e.detail)}</td><td>${e.chain_ok ? '✓' : '✗'}</td></tr>`).join('')}</tbody></table></div>`
      : '<span class="muted">无关联审计</span>';
  } catch (e) { document.getElementById('rel-audit').textContent = e.message; }
}

function approveRelease(id) {
  const close = modal({
    title: '批准发布',
    body: `<p class="sub">批准后系统将按策略快照重新生成脱敏发布包，并写入审计（不可撤回）。请确认风险评估已通过。</p>
      <label class="f">审批人<input id="ap-by" value="${esc(document.getElementById('actor').value)}"></label>
      <label class="f" style="margin-top:10px">审批意见（可选）<input id="ap-note"></label>`,
    foot: `<button data-close>取消</button><button class="primary" id="ap-ok">确认批准并生成发布包</button>`,
  });
  document.getElementById('ap-ok').onclick = async () => {
    const who = document.getElementById('ap-by').value.trim();
    if (!who) return toast('填写审批人', 'err');
    try {
      const r = await api(`/api/releases/${id}/approve`, { method: 'POST', body: { approved_by: who, note: document.getElementById('ap-note').value } });
      close();
      toast('已批准，发布包 SHA-256 ' + r.artifact_sha256.slice(0, 12) + '…', 'ok');
      await renderApproval();
    } catch (e) { toast(e.message, 'err'); }
  };
}

function rejectRelease(id) {
  const close = modal({
    title: '驳回发布',
    body: `<label class="f">驳回原因 *<textarea id="rj-reason" rows="3" placeholder="如：需进一步泛化年龄分段"></textarea></label>`,
    foot: `<button data-close>取消</button><button class="danger" id="rj-ok">确认驳回</button>`,
  });
  document.getElementById('rj-ok').onclick = async () => {
    const reason = document.getElementById('rj-reason').value.trim();
    if (!reason) return toast('请填写驳回原因', 'err');
    try {
      await api(`/api/releases/${id}/reject`, { method: 'POST', body: { reason } });
      close(); toast('已驳回', 'ok'); await renderApproval();
    } catch (e) { toast(e.message, 'err'); }
  };
}

async function exportRelease(id) {
  try {
    const res = await fetch(`/api/releases/${id}/export`, { headers: { 'x-actor': encodeURIComponent(document.getElementById('actor').value) } });
    if (!res.ok) { const t = await res.json().catch(() => ({})); throw new Error(t.error || '导出失败'); }
    const blob = await res.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${id}.zip`;
    document.body.appendChild(a); a.click(); a.remove();
    toast('发布包已开始下载', 'ok');
  } catch (e) { toast(e.message, 'err'); }
}

// ============================================================
// 审计
// ============================================================

async function renderAudit() {
  const r = await api('/api/audit?limit=300');
  const c = document.getElementById('content');
  document.getElementById('head-actions').innerHTML = '<button id="re-verify">重新校验哈希链</button>';
  document.getElementById('re-verify').onclick = async () => { await refreshChain(); toast('已重新校验', 'ok'); };
  const actions = {};
  r.events.forEach((e) => (actions[e.action] = (actions[e.action] || 0) + 1));
  c.innerHTML = `
    <div class="banner ${r.chain_ok ? 'ok' : 'bad'}">
      ${r.chain_ok ? '✓ 审计哈希链完整，记录未被篡改' : '✗ 审计链校验失败，存在被修改的记录'}
      <span style="margin-left:auto" class="small">共 ${r.total} 条事件</span>
    </div>
    <div class="card">
      <h2>检索</h2>
      <div class="row">
        <input id="au-q" placeholder="搜索详情/操作人/动作…" style="flex:1">
        <select id="au-action"><option value="">全部动作</option>${Object.keys(actions).map((a) => `<option value="${esc(a)}">${esc(a)} (${actions[a]})</option>`).join('')}</select>
        <button id="au-go">检索</button>
      </div>
    </div>
    <div class="card">
      <h2>审计日志</h2>
      <p class="sub">每条记录包含前序哈希，任何修改都会导致后续全部记录校验失败。可追溯到发布用了哪套策略（policy_id + 版本）。</p>
      <div class="tbl-wrap" style="max-height:620px"><table>
        <thead><tr><th>#</th><th>时间</th><th>操作人</th><th>动作</th><th>对象</th><th>详情</th><th>链</th></tr></thead>
        <tbody id="au-rows">${auditRows(r.events)}</tbody>
      </table></div>
    </div>`;
  const run = async () => {
    const q = document.getElementById('au-q').value.trim();
    const act = document.getElementById('au-action').value;
    const rr = await api(`/api/audit?limit=300&q=${encodeURIComponent(q)}&action=${encodeURIComponent(act)}`);
    document.getElementById('au-rows').innerHTML = auditRows(rr.events);
  };
  document.getElementById('au-go').onclick = run;
  document.getElementById('au-q').onkeydown = (e) => { if (e.key === 'Enter') run(); };
}

function auditRows(events) {
  return events.map((e) => `<tr>
    <td class="mono tiny">${e.id}</td>
    <td class="tiny nowrap">${esc(e.event_time)}</td>
    <td>${esc(e.actor)}</td>
    <td><span class="chip ${e.action.includes('block') || e.action.includes('reject') ? 'bad' : e.action.includes('approve') ? 'ok' : 'gray'}">${esc(e.action)}</span></td>
    <td class="tiny muted">${[e.dataset_id, e.project_id, e.release_id, e.policy_id].filter(Boolean).map(esc).join('<br>') || '—'}</td>
    <td class="small">${esc(e.detail)}</td>
    <td class="center">${e.chain_ok ? '<span class="pass">✓</span>' : '<span class="fail">✗</span>'}</td>
  </tr>`).join('') || '<tr><td colspan="7" class="empty small">无记录</td></tr>';
}

// ============================================================
// 测试数据与检出率
// ============================================================

async function renderSynthetic() {
  await loadDatasets();
  const last = S.datasets.find((d) => d.source === '合成数据');
  const c = document.getElementById('content');
  document.getElementById('head-actions').innerHTML = '';
  c.innerHTML = `
    <div class="card">
      <h2>生成合成测试数据</h2>
      <p class="sub">生成患者主索引、住院记录、门诊记录、用药记录、临床文本五张表。自由文本中按类型埋入姓名、身份证、手机、住址、病案号、日期，并记录精确字符位置作为真值。</p>
      <div class="row">
        <label class="f">患者例数<input id="syn-n" type="number" value="300" min="50" max="20000"></label>
        <label class="f">随机种子<input id="syn-seed" type="number" value="20260101"></label>
        <label class="f">数据集名称<input id="syn-name" placeholder="留空自动命名" style="min-width:220px"></label>
        <div class="spacer"></div>
        <button class="primary" id="syn-go" style="align-self:flex-end">生成并统计</button>
      </div>
    </div>
    <div id="syn-result">${last ? '<div class="hint">下拉可查看已有合成数据集的最近检测结果，重新生成会得到新数据集。</div>' : ''}</div>
    <div class="card">
      <h2>真实医院数据的接入方式</h2>
      <table>
        <tr><td style="width:180px">门诊 / 住院表</td><td>CSV 首行为表头，字段名使用中文（姓名、身份证号、住院号、入院日期…），系统按字段名与取值形态识别类型。</td></tr>
        <tr><td>自由文本</td><td>把出院小结、病程记录放入独立列，列名含「出院小结」「病程记录」等即可触发文本扫描。</td></tr>
        <tr><td>多表 / 分批</td><td>打包成 ZIP 一次上传；系统用身份证号、病案号、姓名+出生日期做跨表实体关联。</td></tr>
      </table>
    </div>`;
  document.getElementById('syn-go').onclick = async () => {
    const n = +document.getElementById('syn-n').value || 300;
    const seed = +document.getElementById('syn-seed').value || 20260101;
    const name = document.getElementById('syn-name').value.trim();
    const box = document.getElementById('syn-result');
    box.innerHTML = '<div class="card"><div class="muted">生成中…</div></div>';
    try {
      const r = await api('/api/synthetic/generate', { method: 'POST', body: { patients: n, seed, name: name || undefined } });
      box.innerHTML = syntheticReportHtml(r);
      await loadDatasets();
    } catch (e) { box.innerHTML = `<div class="card"><div class="banner bad">${esc(e.message)}</div></div>`; }
  };
}

function syntheticReportHtml(r) {
  const p = r.profile;
  const det = r.free_text_detection;
  const ce = p.column_eval;
  const t = det.totals;
  return `
    <div class="card">
      <div class="banner ok">✓ 已生成数据集「${esc(r.name)}」，ID <span class="mono">${esc(r.id)}</span></div>
      <div class="grid c4">
        <div class="stat"><div class="k">患者</div><div class="v">${p.patients}</div></div>
        <div class="stat"><div class="k">住院/门诊</div><div class="v">${p.inpatient_rows}/${p.outpatient_rows}</div></div>
        <div class="stat"><div class="k">用药/文本</div><div class="v">${p.medication_rows}/${p.note_rows}</div></div>
        <div class="stat"><div class="k">文本真值标识</div><div class="v">${p.truth_spans_total}</div><div class="e">${p.text_chars} 字符</div></div>
      </div>
    </div>
    <div class="card">
      <h2>自由文本标识：检出率与误报率</h2>
      <p class="sub">以埋点真值为准。检出率 = TP/真值；误报率 = 未被真值覆盖的检出/全部检出。</p>
      <div class="kpi-row">
        <div class="kpi"><div class="k">真值</div><div class="v">${t.truth}</div></div>
        <div class="kpi"><div class="k">检出</div><div class="v">${t.detected}</div></div>
        <div class="kpi"><div class="k">检出率</div><div class="v" style="color:#56d364">${pct(t.recall)}</div></div>
        <div class="kpi"><div class="k">准确率</div><div class="v" style="color:#79c0ff">${pct(t.precision)}</div></div>
        <div class="kpi"><div class="k">误报率</div><div class="v" style="color:#ffb6b3">${pct(t.fpr)}</div></div>
      </div>
      <div class="tbl-wrap"><table>
        <thead><tr><th>类型</th><th>真值</th><th>检出</th><th>TP</th><th>FP</th><th>FN</th><th>检出率</th><th>误报率</th></tr></thead>
        <tbody>${det.per_type.map((x) => `<tr>
          <td>${esc(x.pii_type)}</td><td>${x.truth}</td><td>${x.detected}</td><td>${x.tp}</td><td>${x.fp}</td><td>${x.fn_}</td>
          <td class="${x.recall < 0.9 ? 'warn' : 'pass'}">${pct(x.recall)}</td>
          <td class="${x.fpr > 0.1 ? 'fail' : ''}">${pct(x.fpr)}</td></tr>`).join('')}</tbody>
      </table></div>
      ${det.unmatched.length ? `<h3>漏检样例</h3><div class="code">${det.unmatched.slice(0, 15).map((u) => esc(`${u.pii_type} | ${u.text} | ${u.column}`)).join('\n')}</div>` : ''}
      ${det.false_positives?.length ? `<h3>误报样例</h3><div class="code">${det.false_positives.slice(0, 15).map((u) => esc(`${u.pii_type} | ${u.text}`)).join('\n')}</div>` : ''}
    </div>
    <div class="card">
      <h2>结构化字段类型识别准确率</h2>
      <div class="kpi-row">
        <div class="kpi"><div class="k">正确 / 总数</div><div class="v">${ce.correct}/${ce.columns}</div></div>
        <div class="kpi"><div class="k">准确率</div><div class="v" style="color:#56d364">${pct(ce.accuracy)}</div></div>
      </div>
      ${ce.mistakes.length ? `<div class="code">${ce.mistakes.map((m) => esc(`${m.table}.${m.column}: 期望 ${m.expected}，实际 ${m.actual}`)).join('\n')}</div>` : '<p class="pass small">全部字段类型识别正确</p>'}
    </div>
    <div class="card">
      <h2>后续操作</h2>
      <div class="row">
        <button data-goto="#/fields/${r.id}" class="primary">进入字段识别 →</button>
        <button data-goto="#/policy/${r.id}">配置脱敏策略</button>
        <button data-goto="#/risk/${r.id}">风险评估</button>
      </div>
    </div>`;
}

// ============================================================
// boot
// ============================================================

document.addEventListener('click', (e) => {
  const g = e.target.closest('[data-goto]');
  if (g) { location.hash = g.dataset.goto; }
});

window.addEventListener('hashchange', navigate);
window.addEventListener('DOMContentLoaded', async () => {
  await loadDatasets().catch(() => {});
  await navigate();
});
