let workflowHistory = [];
let workflowRunner = null;
const findingDrafts = new Map();
const findingSections = new Map();

function policyMarkup(prefix) {
  return `<div class="policy-grid">
    <div><label for="${prefix}MaxInput">Estimated input-token limit</label><input id="${prefix}MaxInput" type="number" min="2000" max="100000" value="22000"></div>
    <div><label for="${prefix}MaxOutput">Output-token limit</label><input id="${prefix}MaxOutput" type="number" min="512" max="16000" value="5000"></div>
    <div><label for="${prefix}Cost">Workspace cost limit, USD</label><input id="${prefix}Cost" type="number" min="0" max="100" step="0.001" placeholder="Optional; 0 permits free models"></div>
  </div><p class="field-help">Usage includes scan, chat and fix drafts. Cost checks use configured/catalog rates and reserve unknown charges conservatively. OpenRouter receives price ceilings. Direct-provider billing limits remain provider-controlled. Codex dollar usage is unavailable.</p>
  <label>Fallback routes, in order</label><div class="fallback-grid">
    ${[1, 2, 3].map((number) => `<div><select id="${prefix}FallbackModel${number}" aria-label="Fallback model ${number}"><option value="">No fallback</option></select><select id="${prefix}FallbackKey${number}" aria-label="Fallback key ${number}"><option value="">Select API key</option></select></div>`).join('')}
  </div>`;
}

function readWorkflowPolicy(prefix) {
  const fallbacks = [];
  for (let index = 1; index <= 3; index++) {
    const value = $(`${prefix}FallbackModel${index}`).value;
    if (value) fallbacks.push({ model: value === '__codex__' ? '' : value, key_alias: $(`${prefix}FallbackKey${index}`).value });
  }
  return { max_input_tokens: Number($(`${prefix}MaxInput`).value || 22000),
    max_output_tokens: Number($(`${prefix}MaxOutput`).value || 5000),
    max_cost_usd: $(`${prefix}Cost`).value === '' ? null : Number($(`${prefix}Cost`).value), fallbacks };
}

function writeWorkflowPolicy(prefix, policy = {}) {
  $(`${prefix}MaxInput`).value = policy.max_input_tokens || 22000;
  $(`${prefix}MaxOutput`).value = policy.max_output_tokens || 5000;
  $(`${prefix}Cost`).value = policy.max_cost_usd ?? '';
  for (let index = 1; index <= 3; index++) {
    const route = (policy.fallbacks || [])[index - 1];
    $(`${prefix}FallbackModel${index}`).value = route ? route.model || '__codex__' : '';
    $(`${prefix}FallbackKey${index}`).value = route?.key_alias || '';
  }
}

function fillChoices(select, choices) {
  const previous = select.value;
  select.replaceChildren();
  for (const [label, value] of choices) select.add(new Option(label, value));
  select.value = choices.some((choice) => choice[1] === previous) ? previous : choices[0][1];
}

function renderWorkflowChoices() {
  fillChoices($('repairModel'), [['Use scan model', '__scan__'], ['Codex default', ''], ...savedModels.map((model) => [modelLabel(model), model])]);
  fillChoices($('repairKey'), [['Use scan key', '__scan__'], ...savedKeys.map((key) => [key, key])]);
  for (const prefix of ['scan', 'job']) {
    for (let index = 1; index <= 3; index++) {
      fillChoices($(`${prefix}FallbackModel${index}`), [['No fallback', ''], ['Codex default', '__codex__'], ...savedModels.map((model) => [modelLabel(model), model])]);
      fillChoices($(`${prefix}FallbackKey${index}`), [['Select API key', ''], ...savedKeys.map((key) => [key, key])]);
    }
  }
}

function targetRepository(url) {
  try { return new URL(url).pathname.split('/').filter(Boolean).slice(0, 2).join('/').replace(/\.git$/, '').toLowerCase(); }
  catch { return ''; }
}

function updateBaselineChoices() {
  const input = $('repoUrl').value.trim();
  const isPull = /\/pull\/\d+\/?$/.test(input);
  const repository = targetRepository(input);
  const candidates = workflowHistory.filter((scan) => scan.status === 'complete' && targetRepository(scan.url) === repository);
  fillChoices($('baseScan'), [[isPull ? 'PR base and head selected automatically' : 'Full repository review', ''],
    ...candidates.map((scan) => [`${(scan.commit || scan.id).slice(0, 8)} · ${new Date(scan.created_at).toLocaleString()}`, scan.id])]);
  $('baseScan').disabled = isPull;
  if (isPull) $('baseScan').value = '';
}

function updateWorkflowHistory(scans) {
  workflowHistory = scans;
  updateBaselineChoices();
}

function money(value) {
  return typeof value === 'number' && Number.isFinite(value) ? `$${value.toFixed(6)}` : 'unavailable';
}

function table(headers, rows) {
  const wrapper = node('div', 'table-scroll');
  const value = node('table', 'workflow-table');
  const head = node('thead');
  const line = node('tr');
  for (const title of headers) line.append(node('th', '', title));
  head.append(line);
  value.append(head);
  const body = node('tbody');
  for (const values of rows) {
    const row = node('tr');
    for (const text of values) row.append(node('td', '', String(text ?? '—')));
    body.append(row);
  }
  value.append(body);
  wrapper.append(value);
  return wrapper;
}

function renderWorkflowOverview(scan) {
  const coverage = scan.coverage;
  const bar = $('workflowOverview');
  bar.replaceChildren();
  const totals = coverage?.totals || {};
  for (const value of [scan.commit ? `Commit ${scan.commit.slice(0, 8)}` : 'Commit pending',
    coverage ? `${coverage.mode} review` : 'Coverage pending',
    coverage ? `${totals.included || 0} complete / ${totals.partial || 0} partial files` : '',
    workflowRunner?.available ? 'Isolated runner ready' : 'Runner availability pending']) {
    if (value) bar.append(node('span', 'overview-chip', value));
  }
  const operation = scan.operation;
  $('operationStatus').classList.toggle('hidden', !operation || operation.status === 'complete');
  if (operation) {
    $('operationStatus').textContent = operation.status === 'running'
      ? (operation.kind === 'prepare' ? 'Preparing a patch, regression test and PR draft…' : 'Running the same regression on original and patched code…')
      : operation.error || 'Action finished';
  }
  const panel = $('coverageContent');
  panel.replaceChildren();
  if (!coverage) panel.append(node('p', 'field-help', 'Coverage was not recorded for this older scan. Run a fresh review to record it.'));
  else {
    panel.append(node('p', 'field-help', coverage.meaning));
    panel.append(node('p', 'field-help', `Context ${coverage.characters.toLocaleString()} / ${coverage.character_limit.toLocaleString()} characters. Files provided to the model are recorded below.`));
    if (scan.comparison) {
      panel.append(node('p', '', `Compared ${scan.comparison.base_commit.slice(0, 8)} with ${(scan.commit || '').slice(0, 8)}. ${scan.comparison.changed_files.length} tracked files changed.`));
      if (scan.comparison.not_reported_again?.length) panel.append(node('p', 'field-help', `${scan.comparison.not_reported_again.length} previous candidates were not reported again. This is not a verified fix.`));
    }
    panel.append(table(['File', 'Coverage', 'Lines', 'Reason'], coverage.files.slice(0, 300).map((file) => [file.path, file.status, `${file.included_lines}/${file.total_lines ?? '?'}`, file.reason])));
    const download = node('button', 'secondary-button', 'Download full coverage JSON');
    download.type = 'button';
    download.addEventListener('click', () => downloadWorkflowArtifact(`/api/scans/${scan.id}/coverage`, 'coverage.json'));
    panel.append(download);
  }
  const usage = scan.usage || [];
  const policy = scan.policy || {};
  const charged = usage.reduce((sum, item) => sum + (item.charged_or_reserved_usd || 0), 0);
  const usagePanel = $('usageContent');
  usagePanel.replaceChildren(node('p', '', `Recorded or conservatively reserved ${money(charged)} · Limit ${policy.max_cost_usd == null ? 'not set' : money(policy.max_cost_usd)}`));
  usagePanel.append(node('p', 'field-help', 'Actual costs are shown when the provider reports them. Unknown costs retain their reservation. Token estimates can differ from provider tokenization.'));
  usagePanel.append(table(['Action / model', 'Status', 'Input / output', 'Actual USD', 'Reserved USD'], usage.map((item) => [
    `${item.phase} · ${item.model}`, item.status + (item.error ? ` · ${item.error}` : ''),
    `${item.prompt_tokens ?? `~${item.estimated_input_tokens}`} / ${item.completion_tokens ?? '?'}`,
    money(item.actual_cost_usd), money(item.reserved_usd)])));
}

async function downloadWorkflowArtifact(path, filename) {
  try {
    const response = await fetch(path, { headers: { Authorization: `Bearer ${sessionStorage.getItem('trace_access_token') || ''}` } });
    if (!response.ok) throw new Error('Artifact download failed');
    const url = URL.createObjectURL(await response.blob());
    const link = node('a');
    link.href = url;
    link.download = filename;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) { toast(error.message); }
}

async function copyWorkflowText(value) {
  try { await navigator.clipboard.writeText(value); toast('Copied'); }
  catch { toast('Clipboard unavailable. Select and copy the text field.'); }
}

function workflowSection(scanId, findingId, name, title, defaultOpen = false) {
  const details = node('details', 'finding-workflow-section');
  details.append(node('summary', '', title));
  const key = `${scanId}:${findingId}:${name}`;
  details.open = findingSections.get(key) ?? defaultOpen;
  details.addEventListener('toggle', () => findingSections.set(key, details.open));
  return details;
}

function workflowButton(label, callback, disabled = false) {
  const button = node('button', 'secondary-button', label);
  button.type = 'button';
  button.disabled = disabled;
  button.addEventListener('click', callback);
  return button;
}

async function findingAction(scan, finding, action, data = {}) {
  const generation = viewGeneration;
  try {
    await api(`/api/scans/${scan.id}/findings/${finding.id}/${action}`, { method: 'POST', body: JSON.stringify(data) });
    if (currentId === scan.id && generation === viewGeneration) await openScan(scan.id, generation);
    return true;
  } catch (error) { toast(error.message); return false; }
}

function appendFindingTools(card, finding, scan) {
  const busy = scan.operation?.status === 'running' || pendingChats.has(scan.id);
  const draftKey = `${scan.id}:${finding.id}`;
  const draft = findingDrafts.get(draftKey) || {};
  const status = node('div', 'finding-status-row');
  status.append(node('span', 'verification-badge', finding.verification?.status || 'not_run'));
  status.append(node('span', 'field-help', `Fingerprint ${finding.id} · seen in ${finding.seen_in || 1} scan(s)`));
  card.append(status);
  if (finding.assessment) {
    const assessment = node('div', 'candidate-assessment');
    assessment.append(node('strong', '', `Model assessment · ${finding.assessment.verdict}`), node('p', '', finding.assessment.reason));
    card.append(assessment);
  }

  const evidence = workflowSection(scan.id, finding.id, 'evidence', 'Source evidence & attack path');
  if (finding.evidence_view?.function) evidence.append(node('p', 'field-help', `Nearest function declaration: ${finding.evidence_view.function}`));
  evidence.append(node('pre', 'source-evidence', finding.evidence_view?.snippet || 'Source evidence unavailable'));
  for (const step of finding.evidence_view?.flow || []) {
    const line = node('div', 'flow-step');
    line.append(node('strong', '', step.label), node('p', '', step.text));
    evidence.append(line);
  }
  card.append(evidence);

  const triage = workflowSection(scan.id, finding.id, 'triage', `Decision · ${finding.triage?.decision || 'candidate'}`);
  const decision = node('select');
  for (const value of ['candidate', 'accepted', 'dismissed', 'rejected', 'fixed']) decision.add(new Option(value, value));
  decision.value = draft.decision || finding.triage?.decision || 'candidate';
  const note = node('textarea', 'workflow-notes');
  note.placeholder = 'Reason, duplicate link, or false-positive evidence';
  note.value = draft.note ?? finding.triage?.note ?? '';
  const rememberTriage = () => findingDrafts.set(draftKey, { ...findingDrafts.get(draftKey), note: note.value, decision: decision.value });
  decision.addEventListener('change', rememberTriage);
  note.addEventListener('input', rememberTriage);
  triage.append(decision, note, workflowButton('Save decision for future scans', async () => {
    const saved = await findingAction(scan, finding, 'triage', { decision: decision.value, note: note.value });
    if (saved) findingDrafts.delete(draftKey);
  }));
  card.append(triage);

  const actions = node('div', 'finding-actions');
  actions.append(workflowButton('Draft fix & PR', async () => {
    const selected = $('repairModel').value;
    const key = $('repairKey').value;
    findingDrafts.delete(draftKey);
    await findingAction(scan, finding, 'prepare', {
      model: selected === '__scan__' ? scan.model : selected,
      key_alias: key === '__scan__' ? scan.key_alias : key,
    });
  }, busy));
  actions.append(workflowButton('Run isolated regression', () => findingAction(scan, finding, 'verify'), busy || !finding.remediation?.valid));
  card.append(actions);

  if (finding.remediation?.valid) {
    const plan = finding.remediation;
    const section = workflowSection(scan.id, finding.id, 'plan', 'Review / edit patch and regression plan', true);
    section.append(node('p', 'field-help', 'Review the diff and command before verification. The runner has no network, credentials, or writable host checkout.'));
    const fields = {};
    for (const [key, title] of [['fix_patch', 'Source patch'], ['test_patch', 'Regression-test patch'], ['command', 'Test command as an argument array'],
      ['failure_marker', 'Expected original-code failure marker'], ['success_marker', 'Expected patched-code success marker']]) {
      section.append(node('label', '', title));
      const input = node(key.endsWith('patch') ? 'textarea' : 'input', key.endsWith('patch') ? 'patch-editor' : 'workflow-input');
      input.value = draft[key] ?? (key === 'command' ? JSON.stringify(plan.command) : plan[key]);
      input.disabled = busy;
      input.addEventListener('input', () => findingDrafts.set(draftKey, { ...findingDrafts.get(draftKey), [key]: input.value }));
      fields[key] = input;
      section.append(input);
    }
    section.append(workflowButton('Save edited plan', async () => {
      try {
        const changed = { ...plan, fix_patch: fields.fix_patch.value, test_patch: fields.test_patch.value,
          command: JSON.parse(fields.command.value), failure_marker: fields.failure_marker.value, success_marker: fields.success_marker.value };
        const saved = await findingAction(scan, finding, 'plan', { plan: changed });
        if (saved) findingDrafts.delete(draftKey);
      } catch (error) { toast(error.message); }
    }, busy));
    card.append(section);
  }

  const verification = finding.verification || {};
  if (verification.status && verification.status !== 'not_run') {
    const section = workflowSection(scan.id, finding.id, 'verification', `Regression evidence · ${verification.status}`, true);
    section.append(node('p', '', verification.reason || ''));
    for (const kind of ['baseline', 'patched']) if (verification[kind]) {
      section.append(node('strong', '', `${kind} · exit ${verification[kind].exit_code}`));
      section.append(node('pre', 'verification-output', verification[kind].output));
    }
    card.append(section);
  }

  const pr = workflowSection(scan.id, finding.id, 'pr', finding.pr?.ready ? 'PR package · regression verified' : 'PR draft · verification pending');
  const document = finding.pr || {};
  const title = node('input', 'workflow-input');
  title.value = document.title || finding.title;
  title.readOnly = true;
  const body = node('textarea', 'pr-body');
  body.value = document.body || '';
  body.readOnly = true;
  const buttons = node('div', 'finding-actions');
  buttons.append(workflowButton('Copy PR title', () => copyWorkflowText(title.value)),
    workflowButton('Copy full PR body', () => copyWorkflowText(body.value)),
    workflowButton('Download patch & evidence bundle', () => downloadWorkflowArtifact(`/api/scans/${scan.id}/findings/${finding.id}/bundle`, `trace-pr-${finding.id}.zip`), !finding.remediation?.valid));
  pr.append(title, body, buttons);
  const commands = node('pre', 'apply-commands', document.apply_commands || '');
  pr.append(node('p', 'field-help', 'Apply the downloaded patches on your own branch, review the diff, then paste the PR title and body.'), commands,
    workflowButton('Copy branch / apply commands', () => copyWorkflowText(document.apply_commands || ''), !finding.remediation?.valid));
  card.append(pr);
}

function initializeWorkflowUI() {
  $('scanPolicyFields').innerHTML = policyMarkup('scan');
  $('jobPolicyFields').innerHTML = policyMarkup('job');
  const pricing = node('div', 'pricing-grid');
  for (const [id, title] of [['inputPrice', 'Input USD / million tokens'], ['outputPrice', 'Output USD / million tokens']]) {
    const group = node('div');
    const label = node('label', '', title);
    label.htmlFor = id;
    const input = node('input');
    input.id = id;
    input.type = 'number';
    input.min = '0';
    input.step = '0.001';
    input.placeholder = 'Optional pricing for cost limits';
    group.append(label, input);
    pricing.append(group);
  }
  $('modelForm').insertBefore(pricing, $('savedModels'));
  $('repoUrl').addEventListener('input', updateBaselineChoices);
  $('showDismissed').addEventListener('change', () => { if (activeScan) renderScan(activeScan); });
  $('editBudget').addEventListener('click', () => {
    if (!activeScan) return;
    writeWorkflowPolicy('job', activeScan.policy || {});
    $('budgetDialog').showModal();
  });
  $('closeBudget').addEventListener('click', () => $('budgetDialog').close());
  $('budgetForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!activeScan) return;
    const id = activeScan.id;
    try {
      await api(`/api/scans/${id}/budget`, { method: 'POST', body: JSON.stringify(readWorkflowPolicy('job')) });
      $('budgetDialog').close();
      if (currentId === id) await openScan(id, viewGeneration);
    } catch (error) { toast(error.message); }
  });
  renderWorkflowChoices();
  api('/api/runner').then((result) => {
    workflowRunner = result;
    if (activeScan) renderWorkflowOverview(activeScan);
  }).catch(() => {});
}
