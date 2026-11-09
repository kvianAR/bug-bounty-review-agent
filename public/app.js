const $ = (id) => document.getElementById(id);
let currentId = null;
let pollTimer = null;
let toastTimer = null;
let savedModels = [];
let savedKeys = [];
let savedProviders = [];
let catalogTimer = null;

async function api(path, options = {}) {
  const response = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...options });
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
  } catch (error) { list.replaceChildren(node('small', '', error.message)); }
}

function updateKeyRows() {
  $('scanKeyRow').classList.toggle('hidden', !requiresKey($('scanModel').value));
  $('chatKeyRow').classList.toggle('hidden', !requiresKey($('chatModel').value));
}

function showWelcome() {
  currentId = null;
  clearTimeout(pollTimer);
  $('welcome').classList.remove('hidden');
  $('workspace').classList.add('hidden');
  $('crumb').textContent = 'New scan';
  document.querySelectorAll('.history-item').forEach((el) => el.classList.remove('active'));
  $('repoUrl').focus();
}

async function loadHistory() {
  const data = await api('/api/scans');
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
  $('welcome').classList.add('hidden');
  $('workspace').classList.remove('hidden');
  $('crumb').textContent = repoName(scan.url);
  $('repoName').textContent = repoName(scan.url);
  $('repoLink').href = scan.url;
  $('statusPill').textContent = scan.status;
  $('statusPill').title = `Scan model: ${scan.model ? modelLabel(scan.model) : 'Codex default'}`;
  $('statusPill').className = `status-pill ${scan.status}`;
  const done = scan.status === 'complete';
  $('chatInput').disabled = !done;
  $('sendChat').disabled = !done;
  $('scanProgress').classList.toggle('hidden', done);
  $('summary').classList.toggle('hidden', !done);
  $('limitations').classList.toggle('hidden', !done);
  $('downloadReport').classList.toggle('hidden', !done);
  $('downloadReport').href = `/api/scans/${scan.id}/report`;
  $('findings').replaceChildren();
  $('findingCount').textContent = done ? `${scan.report.findings.length} CANDIDATE${scan.report.findings.length === 1 ? '' : 'S'}` : '—';
  if (done) {
    $('summary').replaceChildren(node('strong', '', 'REVIEW SUMMARY'), node('span', '', scan.report.summary));
    const findings = scan.report.findings;
    if (!findings.length) $('findings').append(node('div', 'summary', 'No source-backed candidate findings in this scan. This does not prove the repository is secure.'));
    for (const finding of findings) $('findings').append(renderFinding(finding));
    const limits = $('limitations');
    limits.replaceChildren(node('strong', '', 'LIMITS  '));
    limits.append(node('span', '', scan.report.limitations.join(' · ') || 'Confirm findings under the program rules.'));
    renderMessages(scan.messages);
  } else {
    const title = $('scanProgress').querySelector('strong');
    const detail = $('scanProgress').querySelector('p');
    title.textContent = scan.status === 'cloning' ? 'Fetching repository' : scan.status === 'reviewing' ? 'Tracing code paths' : scan.status === 'queued' ? 'Preparing review' : 'Review stopped';
    detail.textContent = scan.error || (scan.status === 'reviewing' ? 'Codex is reviewing source. This may take several minutes.' : 'Waiting for agent…');
    $('scanProgress').querySelector('.spinner').classList.toggle('hidden', ['failed', 'interrupted'].includes(scan.status));
  }
}

async function openScan(id) {
  currentId = id;
  clearTimeout(pollTimer);
  try {
    const scan = await api(`/api/scans/${id}`);
    if (currentId !== id) return;
    renderScan(scan);
    await loadHistory();
    if (['queued', 'cloning', 'reviewing'].includes(scan.status)) pollTimer = setTimeout(() => openScan(id), 3000);
  } catch (error) { toast(error.message); }
}

$('scanForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('submitScan');
  button.disabled = true;
  button.textContent = 'Starting…';
  try {
    const scan = await api('/api/scans', { method: 'POST', body: JSON.stringify({ url: $('repoUrl').value.trim(), focus: $('focus').value.trim(), model: $('scanModel').value, key_alias: $('scanKey').value }) });
    await openScan(scan.id);
  } catch (error) { toast(error.message); }
  finally { button.disabled = false; button.innerHTML = 'Start scan <span>→</span>'; }
});

$('chatForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!currentId) return;
  const question = $('chatInput').value.trim();
  if (!question) return;
  $('chatInput').value = '';
  $('chatInput').disabled = true;
  $('sendChat').disabled = true;
  const id = currentId;
  const thinking = { role: 'assistant', content: 'Thinking…' };
  try {
    const scan = await api(`/api/scans/${id}`);
    renderMessages([...(scan.messages || []), { role: 'user', content: question }, thinking]);
    const result = await api(`/api/scans/${id}/chat`, { method: 'POST', body: JSON.stringify({ message: question, model: $('chatModel').value, key_alias: $('chatKey').value }) });
    if (currentId === id) renderMessages(result.messages);
  } catch (error) { toast(error.message); $('chatInput').value = question; }
  finally { if (currentId === id) { $('chatInput').disabled = false; $('sendChat').disabled = false; $('chatInput').focus(); } }
});

$('chatInput').addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); $('chatForm').requestSubmit(); }
});
$('newScan').addEventListener('click', showWelcome);
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
    let model = $('modelId').value.trim();
    if (provider === 'openrouter' && $('floorMode').checked && !/:(floor|free|nitro)$/.test(model)) model += ':floor';
    const providerName = $('customProvider').value;
    const data = await api('/api/models', { method: 'POST', body: JSON.stringify({ id: model, provider, provider_name: providerName }) });
    savedModels = data.models;
    renderModels();
    const selected = provider === 'openrouter' ? `openrouter|${model}` : provider === 'custom' ? `custom|${providerName}|${model}` : model;
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
loadHistory().catch((error) => toast(error.message));
loadModels().catch((error) => toast(error.message));
loadKeys().catch((error) => toast(error.message));
loadProviders().catch((error) => toast(error.message));
