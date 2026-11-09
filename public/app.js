const $ = (id) => document.getElementById(id);
const accessToken = new URLSearchParams(location.hash.slice(1)).get('token');
if (accessToken) {
  sessionStorage.setItem('trace_access_token', accessToken);
  history.replaceState(null, '', location.pathname);
}
let currentId = null;
let activeScan = null;
let viewGeneration = 0;
const pendingChats = new Set();
let pollTimer = null;
let toastTimer = null;
let savedModels = [];
let savedKeys = [];
let savedProviders = [];
let githubAccounts = [];
let catalogTimer = null;

async function api(path, options = {}) {
  const response = await fetch(path, { ...options, headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${sessionStorage.getItem('trace_access_token') || ''}`,
    ...options.headers,
  } });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function toast(message) {
  $('toast').textContent = message;
  $('toast').classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => $('toast').classList.add('hidden'), 5000);
}

function repoName(url) {
  try { return new URL(url).pathname.replace(/^\//, '').replace(/\.git$/, ''); }
  catch { return url; }
}

function node(tag, className, value) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (value !== undefined) el.textContent = value;
  return el;
}

function modelLabel(model) {
  if (model.startsWith('openrouter|')) return `OpenRouter · ${model.slice(11)}`;
  if (model.startsWith('custom|')) {
    const [, provider, id] = model.split('|');
    return `${provider} · ${id}`;
  }
  return `Codex · ${model}`;
}

function requiresKey(model) { return model.startsWith('openrouter|') || model.startsWith('custom|'); }

function renderModels() {
  for (const id of ['scanModel', 'chatModel']) {
    const select = $(id);
    const previous = select.value;
    select.replaceChildren(new Option('Codex default', ''));
    for (const model of savedModels) select.add(new Option(modelLabel(model), model));
    select.value = savedModels.includes(previous) ? previous : '';
  }
  const list = $('savedModels');
  list.replaceChildren();
  for (const model of savedModels) {
    const badge = node('span', 'model-badge');
    badge.append(node('span', '', modelLabel(model)));
    const test = node('button', 'test-model', 'Test');
    test.type = 'button';
    test.setAttribute('aria-label', `Test ${model}`);
    test.addEventListener('click', async () => {
      const keyAlias = $('testKey').value;
      if (requiresKey(model) && !keyAlias) return toast('Select a key for this model test');
      $('modelTestResult').textContent = `Testing ${modelLabel(model)}…`;
      test.disabled = true;
      try {
        const result = await api('/api/models/test', { method: 'POST', body: JSON.stringify({ model, key_alias: keyAlias }) });
        $('modelTestResult').textContent = `Working: ${result.answer}`;
      } catch (error) { $('modelTestResult').textContent = `Failed: ${error.message}`; }
      finally { test.disabled = false; }
    });
    const remove = node('button', '', '×');
    remove.type = 'button';
    remove.setAttribute('aria-label', `Delete ${model}`);
    remove.addEventListener('click', async () => {
      try {
        const data = await api('/api/models', { method: 'DELETE', body: JSON.stringify({ model }) });
        savedModels = data.models;
        renderModels();
        toast(`Model ${model} deleted`);
      } catch (error) { toast(error.message); }
    });
    badge.append(test, remove);
    list.append(badge);
  }
  updateKeyRows();
  renderWorkflowChoices();
}

async function loadModels() {
  const data = await api('/api/models');
  savedModels = data.models;
  renderModels();
}

function renderKeys() {
  for (const id of ['scanKey', 'chatKey', 'testKey']) {
    const select = $(id);
    const previous = select.value;
    select.replaceChildren(new Option('Select key', ''));
    for (const alias of savedKeys) select.add(new Option(alias, alias));
    select.value = savedKeys.includes(previous) ? previous : '';
  }
  const list = $('savedKeys');
  list.replaceChildren();
  for (const alias of savedKeys) {
    const badge = node('span', 'model-badge');
    badge.append(node('span', '', alias));
    const remove = node('button', '', '×');
    remove.type = 'button';
    remove.setAttribute('aria-label', `Delete key ${alias}`);
    remove.addEventListener('click', async () => {
      try {
        const data = await api('/api/keys', { method: 'DELETE', body: JSON.stringify({ alias }) });
        savedKeys = data.keys;
        renderKeys();
        toast(`Key ${alias} deleted`);
      } catch (error) { toast(error.message); }
    });
    badge.append(remove);
    list.append(badge);
  }
  renderWorkflowChoices();
}

async function loadKeys() {
  const data = await api('/api/keys');
  savedKeys = data.keys;
  renderKeys();
}

function renderProviders() {
  const select = $('customProvider');
  const previous = select.value;
  select.replaceChildren(new Option('Select provider', ''));
  const list = $('savedProviders');
  list.replaceChildren();
  for (const provider of savedProviders) {
    select.add(new Option(provider.name, provider.name));
    list.append(node('span', '', provider.name));
  }
  select.value = savedProviders.some((provider) => provider.name === previous) ? previous : '';
}

async function loadProviders() {
  const data = await api('/api/providers');
  savedProviders = data.providers;
  renderProviders();
}

async function loadGithubAccounts() {
  const data = await api('/api/github/accounts');
  githubAccounts = Array.isArray(data.accounts) ? data.accounts : [];
  const select = $('githubAccount');
  const previous = select.value;
  select.replaceChildren(new Option('Public repositories', ''));
  for (const account of githubAccounts) select.add(new Option(`${account.login} · signed in`, account.login));
  select.value = githubAccounts.some((account) => account.login === previous) ? previous : '';
}

async function searchCatalog(query) {
  const list = $('catalogResults');
  if (!query.trim()) { list.replaceChildren(); return; }
  try {
    const data = await api(`/api/openrouter/models?q=${encodeURIComponent(query.trim())}`);
    if ($('catalogSearch').value.trim() !== query.trim()) return;
    list.replaceChildren();
    for (const model of data.models.slice(0, 8)) {
      const button = node('button', '', `${model.name} · ${model.id}`);
      button.type = 'button';
      button.addEventListener('click', () => { $('modelId').value = model.id; list.replaceChildren(); });
      list.append(button);
    }
    if (!data.models.length) list.append(node('small', '', 'No matching model. You can paste an ID directly.'));
  } catch (error) {
    if ($('catalogSearch').value.trim() === query.trim()) list.replaceChildren(node('small', '', error.message));
  }
}

function updateKeyRows() {
  $('scanKeyRow').classList.toggle('hidden', !requiresKey($('scanModel').value));
  $('chatKeyRow').classList.toggle('hidden', !requiresKey($('chatModel').value));
}

function showWelcome() {
  viewGeneration += 1;
  currentId = null;
  activeScan = null;
  clearTimeout(pollTimer);
  $('welcome').classList.remove('hidden');
  $('workspace').classList.add('hidden');
  $('crumb').textContent = 'New scan';
  document.querySelectorAll('.history-item').forEach((el) => el.classList.remove('active'));
  $('repoUrl').focus();
}

async function loadHistory() {
  const data = await api('/api/scans');
  updateWorkflowHistory(data.scans);
  const container = $('history');
  container.replaceChildren();
  $('scanCount').textContent = data.scans.length;
  if (!data.scans.length) container.append(node('p', 'history-empty', 'No scans yet.'));
  for (const scan of data.scans) {
    const item = node('button', 'history-item' + (scan.id === currentId ? ' active' : ''));
    item.type = 'button';
    item.append(node('span', 'history-icon', '⌁'));
    const body = node('span');
    body.append(node('span', '', repoName(scan.url)));
    body.append(node('small', '', scan.status.toUpperCase()));
    item.append(body);
    item.addEventListener('click', () => openScan(scan.id));
    container.append(item);
  }
}

function renderFinding(finding) {
  const card = node('article', 'finding-card');
  const top = node('div', 'finding-top');
  top.append(node('div', 'finding-title', finding.title));
  top.append(node('span', `severity ${finding.severity}`, finding.severity.toUpperCase()));
  card.append(top);
  card.append(node('div', 'finding-meta', `${finding.path}:${finding.line}  ·  ${finding.cwe}  ·  ${finding.confidence} confidence`));
  const details = node('dl');
  for (const [label, value] of [['Evidence', finding.evidence], ['Impact', finding.impact], ['Safe reproduction', finding.reproduction], ['Suggested fix', finding.fix]]) {
    details.append(node('dt', '', label));
    details.append(node('dd', '', value));
  }
  card.append(details);
  const more = node('details');
  more.append(node('summary', '', 'PR checklist'));
  const list = node('ul');
  for (const step of finding.pr_checklist || []) list.append(node('li', '', step));
  more.append(list);
  card.append(more);
  appendFindingTools(card, finding, activeScan);
  return card;
}

function renderMessages(messages) {
  const container = $('messages');
  container.replaceChildren();
  const intro = node('div', 'assistant-message');
  intro.append(node('div', 'avatar', 'T'));
  const introBody = node('div', 'message-body');
  introBody.append(node('small', '', 'TRACE AGENT'));
  introBody.append(node('p', '', 'Ask about findings, attack paths, fixes, or what to test before a PR.'));
  intro.append(introBody);
  container.append(intro);
  for (const message of messages || []) {
    const row = node('div', message.role === 'user' ? 'user-message' : 'assistant-message');
    if (message.role !== 'user') row.append(node('div', 'avatar', 'T'));
    const body = node('div', 'message-body');
    if (message.role !== 'user') body.append(node('small', '', `TRACE AGENT · ${message.model ? modelLabel(message.model) : 'Codex default'}`));
    body.append(node('p', '', message.content));
    row.append(body);
    container.append(row);
  }
  container.scrollTop = container.scrollHeight;
}

function renderScan(scan) {
  activeScan = scan;
  renderWorkflowOverview(scan);
  $('welcome').classList.add('hidden');
  $('workspace').classList.remove('hidden');
  $('crumb').textContent = repoName(scan.url);
  $('repoName').textContent = repoName(scan.url);
  $('repoLink').href = scan.url;
  $('statusPill').textContent = scan.status;
  $('statusPill').title = `Scan model: ${scan.model ? modelLabel(scan.model) : 'Codex default'}`;
  $('statusPill').className = `status-pill ${scan.status}`;
  const done = scan.status === 'complete';
  const failed = ['failed', 'interrupted'].includes(scan.status);
  $('deleteScan').disabled = !['complete', 'failed', 'interrupted'].includes(scan.status) || pendingChats.has(scan.id) || scan.operation?.status === 'running';
  $('retryScan').classList.toggle('hidden', !failed);
  $('chatInput').disabled = !done || pendingChats.has(scan.id);
  $('sendChat').disabled = !done || pendingChats.has(scan.id);
  $('scanProgress').classList.toggle('hidden', done);
  $('summary').classList.toggle('hidden', !done);
  $('limitations').classList.toggle('hidden', !done);
  $('downloadReport').classList.toggle('hidden', !done);
  $('downloadReport').href = `/api/scans/${scan.id}/report`;
  $('findings').replaceChildren();
  $('findingCount').textContent = done ? `${scan.report.findings.length} CANDIDATE${scan.report.findings.length === 1 ? '' : 'S'}` : '—';
  if (done) {
    $('summary').replaceChildren(node('strong', '', 'REVIEW SUMMARY'), node('span', '', scan.report.summary));
    const findings = scan.report.findings.filter((finding) => $('showDismissed').checked || !['dismissed', 'rejected'].includes(finding.triage?.decision));
    const hidden = scan.report.findings.length - findings.length;
    $('findingCount').textContent = `${scan.report.findings.length} CANDIDATE${scan.report.findings.length === 1 ? '' : 'S'}${hidden ? ` · ${hidden} dismissed hidden` : ''}`;
    if (!findings.length) $('findings').append(node('div', 'summary', hidden ? 'Saved decisions hide these findings. Enable Show dismissed findings to review them.' : 'No source-backed candidate findings in this scan. This does not prove the repository is secure.'));
    for (const finding of findings) $('findings').append(renderFinding(finding));
    const limits = $('limitations');
    limits.replaceChildren(node('strong', '', 'LIMITS  '));
    limits.append(node('span', '', scan.report.limitations.join(' · ') || 'Confirm findings under the program rules.'));
    renderMessages(scan.messages);
  } else {
    renderMessages(scan.messages || []);
    const title = $('scanProgress').querySelector('strong');
    const detail = $('scanProgress').querySelector('p');
    const errorTitles = { repository_access_required: 'Repository access required', provider_timeout: 'Model response timed out' };
    const progressTitles = { cloning: 'Fetching repository', reviewing: 'Tracing code paths', queued: 'Preparing review' };
    title.textContent = errorTitles[scan.error_code] || progressTitles[scan.status] || 'Review stopped';
    detail.textContent = scan.error || (scan.status === 'reviewing' ? 'Codex is reviewing source. This may take several minutes.' : 'Waiting for agent…');
    $('scanProgress').querySelector('.spinner').classList.toggle('hidden', ['failed', 'interrupted'].includes(scan.status));
  }
}

async function openScan(id, generation = null) {
  if (generation !== null && (generation !== viewGeneration || id !== currentId)) return;
  if (generation === null) {
    generation = ++viewGeneration;
    currentId = id;
    $('chatInput').value = '';
    renderMessages([]);
  }
  clearTimeout(pollTimer);
  try {
    const scan = await api(`/api/scans/${id}`);
    if (currentId !== id || generation !== viewGeneration) return;
    renderScan(scan);
    await loadHistory();
    if (currentId !== id || generation !== viewGeneration) return;
    if (['queued', 'cloning', 'reviewing'].includes(scan.status) || scan.operation?.status === 'running') pollTimer = setTimeout(() => openScan(id, generation), 3000);
  } catch (error) { toast(error.message); }
}

$('scanForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('submitScan');
  button.disabled = true;
  button.textContent = 'Starting…';
  const generation = viewGeneration;
  try {
    const scan = await api('/api/scans', { method: 'POST', body: JSON.stringify({ url: $('repoUrl').value.trim(), github_account: $('githubAccount').value, focus: $('focus').value.trim(), model: $('scanModel').value, key_alias: $('scanKey').value, base_scan: $('baseScan').value, policy: readWorkflowPolicy('scan') }) });
    if (generation === viewGeneration) await openScan(scan.id);
    else await loadHistory();
  } catch (error) { toast(error.message); }
  finally { button.disabled = false; button.innerHTML = 'Start scan <span>→</span>'; }
});

$('chatForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!currentId) return;
  const question = $('chatInput').value.trim();
  if (!question || pendingChats.has(currentId)) return;
  const id = currentId;
  const generation = viewGeneration;
  const model = $('chatModel').value;
  const keyAlias = $('chatKey').value;
  pendingChats.add(id);
  $('deleteScan').disabled = true;
  $('chatInput').value = '';
  $('chatInput').disabled = true;
  $('sendChat').disabled = true;
  const thinking = { role: 'assistant', content: 'Thinking…' };
  try {
    const scan = await api(`/api/scans/${id}`);
    if (currentId === id && generation === viewGeneration) renderMessages([...(scan.messages || []), { role: 'user', content: question }, thinking]);
    const result = await api(`/api/scans/${id}/chat`, { method: 'POST', body: JSON.stringify({ message: question, model, key_alias: keyAlias }) });
    if (currentId === id && generation === viewGeneration) renderMessages(result.messages);
  } catch (error) {
    toast(error.message);
    if (currentId === id && generation === viewGeneration) $('chatInput').value = question;
  } finally {
    pendingChats.delete(id);
    if (currentId === id) {
      $('deleteScan').disabled = false;
      $('chatInput').disabled = false;
      $('sendChat').disabled = false;
      if (generation === viewGeneration) $('chatInput').focus();
      openScan(id, viewGeneration);
    }
  }
});

$('downloadReport').addEventListener('click', async (event) => {
  event.preventDefault();
  const id = currentId;
  if (!id) return;
  try {
    const response = await fetch(`/api/scans/${id}/report`, {
      headers: { 'Authorization': `Bearer ${sessionStorage.getItem('trace_access_token') || ''}` },
    });
    if (!response.ok) throw new Error('Report download failed');
    const url = URL.createObjectURL(await response.blob());
    const download = node('a');
    download.href = url;
    download.download = 'security-report.md';
    download.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) { toast(error.message); }
});

$('chatInput').addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); $('chatForm').requestSubmit(); }
});
$('newScan').addEventListener('click', showWelcome);
$('retryScan').addEventListener('click', () => {
  if (!activeScan) return;
  const scan = activeScan;
  showWelcome();
  $('repoUrl').value = scan.target_url || scan.url;
  const owner = repoName(scan.url).split('/')[0];
  const account = scan.github_account || (scan.error_code === 'repository_access_required' && githubAccounts.some((item) => item.login === owner) ? owner : '');
  $('githubAccount').value = account;
  $('focus').value = scan.focus || '';
  $('scanModel').value = savedModels.includes(scan.model) ? scan.model : '';
  $('scanKey').value = savedKeys.includes(scan.key_alias) ? scan.key_alias : '';
  writeWorkflowPolicy('scan', scan.policy || {});
  updateBaselineChoices();
  $('baseScan').value = scan.base_scan || '';
  updateKeyRows();
});
$('deleteScan').addEventListener('click', async () => {
  const id = currentId;
  const generation = viewGeneration;
  if (!id || !confirm('Delete this scan, its report, chat history, and local repository checkout? Saved repository triage decisions remain for future scans.')) return;
  $('deleteScan').disabled = true;
  try {
    await api(`/api/scans/${id}`, { method: 'DELETE', body: JSON.stringify({}) });
    if (currentId === id && generation === viewGeneration) showWelcome();
    await loadHistory();
    toast('Scan deleted');
  } catch (error) { toast(error.message); }
  finally { if (currentId === id && generation === viewGeneration) $('deleteScan').disabled = false; }
});
$('scanModel').addEventListener('change', updateKeyRows);
$('chatModel').addEventListener('change', updateKeyRows);
$('modelProvider').addEventListener('change', () => {
  const openrouter = $('modelProvider').value === 'openrouter';
  const custom = $('modelProvider').value === 'custom';
  $('floorLabel').classList.toggle('hidden', !openrouter);
  $('catalogRow').classList.toggle('hidden', !openrouter);
  $('customModelRow').classList.toggle('hidden', !custom);
  $('modelId').placeholder = openrouter ? 'Paste provider/model:free or provider/model:floor' : custom ? 'Provider model ID' : 'e.g. gpt-6.1-sol';
});
$('catalogSearch').addEventListener('input', () => {
  clearTimeout(catalogTimer);
  const query = $('catalogSearch').value;
  catalogTimer = setTimeout(() => searchCatalog(query), 250);
});
$('deepseekPreset').addEventListener('click', () => {
  $('providerName').value = 'DeepSeek';
  $('providerEndpoint').value = 'https://api.deepseek.com/chat/completions';
});
$('mimoPreset').addEventListener('click', () => {
  $('providerName').value = 'MiMo';
  $('providerEndpoint').value = 'https://api.xiaomimimo.com/v1/chat/completions';
});
$('manageModels').addEventListener('click', () => $('modelDialog').showModal());
$('addModelInline').addEventListener('click', () => $('modelDialog').showModal());
$('closeModels').addEventListener('click', () => $('modelDialog').close());
$('cancelModels').addEventListener('click', () => $('modelDialog').close());
$('modelForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const provider = $('modelProvider').value;
    const inputRate = $('inputPrice').value;
    const outputRate = $('outputPrice').value;
    if ((inputRate === '') !== (outputRate === '')) throw new Error('Enter both input and output prices, or leave both empty');
    let model = $('modelId').value.trim();
    if (provider === 'openrouter' && $('floorMode').checked && !/:(floor|free|nitro)$/.test(model)) model += ':floor';
    const providerName = $('customProvider').value;
    const data = await api('/api/models', { method: 'POST', body: JSON.stringify({ id: model, provider, provider_name: providerName }) });
    savedModels = data.models;
    renderModels();
    const selected = provider === 'openrouter' ? `openrouter|${model}` : provider === 'custom' ? `custom|${providerName}|${model}` : model;
    if (inputRate !== '' && outputRate !== '') await api('/api/model-prices', { method: 'POST', body: JSON.stringify({ model: selected, input: Number(inputRate), output: Number(outputRate), request: 0 }) });
    $('scanModel').value = selected;
    $('chatModel').value = selected;
    updateKeyRows();
    $('modelId').value = '';
    $('floorMode').checked = false;
    toast(`Model ${model} saved`);
  } catch (error) { toast(error.message); }
});
$('providerForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const name = $('providerName').value.trim();
    const endpoint = $('providerEndpoint').value.trim();
    const data = await api('/api/providers', { method: 'POST', body: JSON.stringify({ name, endpoint }) });
    savedProviders = data.providers;
    renderProviders();
    $('modelProvider').value = 'custom';
    $('modelProvider').dispatchEvent(new Event('change'));
    $('customProvider').value = name;
    $('providerName').value = '';
    $('providerEndpoint').value = '';
    toast(`Provider ${name} saved`);
  } catch (error) { toast(error.message); }
});
$('keyForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const alias = $('keyAlias').value.trim();
    const data = await api('/api/keys', { method: 'POST', body: JSON.stringify({ alias, key: $('apiKey').value.trim() }) });
    savedKeys = data.keys;
    renderKeys();
    $('scanKey').value = alias;
    $('chatKey').value = alias;
    $('testKey').value = alias;
    $('keyAlias').value = '';
    $('apiKey').value = '';
    toast(`Key ${alias} added for this session`);
  } catch (error) { toast(error.message); }
});
document.addEventListener('keydown', (event) => {
  if (event.key.toLowerCase() === 'n' && !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) showWelcome();
});
initializeWorkflowUI();
loadHistory().catch((error) => toast(error.message));
loadModels().catch((error) => toast(error.message));
loadKeys().catch((error) => toast(error.message));
loadProviders().catch((error) => toast(error.message));
loadGithubAccounts().catch(() => { $('githubAccessNote').textContent = 'GitHub account lookup failed. Sign in with GitHub CLI to scan private repositories.'; });
