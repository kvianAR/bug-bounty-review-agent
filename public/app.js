const $ = (id) => document.getElementById(id);
let currentId = null;
let pollTimer = null;
let toastTimer = null;

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
    if (message.role !== 'user') body.append(node('small', '', 'TRACE AGENT'));
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
    const scan = await api('/api/scans', { method: 'POST', body: JSON.stringify({ url: $('repoUrl').value.trim(), focus: $('focus').value.trim() }) });
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
    const result = await api(`/api/scans/${id}/chat`, { method: 'POST', body: JSON.stringify({ message: question }) });
    if (currentId === id) renderMessages(result.messages);
  } catch (error) { toast(error.message); $('chatInput').value = question; }
  finally { if (currentId === id) { $('chatInput').disabled = false; $('sendChat').disabled = false; $('chatInput').focus(); } }
});

$('chatInput').addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); $('chatForm').requestSubmit(); }
});
$('newScan').addEventListener('click', showWelcome);
document.addEventListener('keydown', (event) => {
  if (event.key.toLowerCase() === 'n' && !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) showWelcome();
});
loadHistory().catch((error) => toast(error.message));
