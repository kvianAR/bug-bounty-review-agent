const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

class Element {
  constructor(tag = 'div') {
    this.tagName = tag.toUpperCase();
    this.value = '';
    this.textContent = '';
    this.children = [];
    this.listeners = {};
    this.attributes = {};
    this.classes = new Set();
    this.classList = {
      add: (name) => this.classes.add(name),
      remove: (name) => this.classes.delete(name),
      toggle: (name, enabled) => enabled ? this.classes.add(name) : this.classes.delete(name),
    };
    this.parts = {};
  }
  addEventListener(event, handler) { this.listeners[event] = handler; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  add(option) { this.children.push(option); }
  setAttribute(name, value) { this.attributes[name] = value; }
  querySelector(selector) { return this.parts[selector] ||= new Element(); }
  focus() {}
  click() {}
  close() {}
  showModal() {}
}

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

function response(data, ok = true) {
  return { ok, status: ok ? 200 : 500, json: async () => data };
}

function job(id, status = 'reviewing') {
  return { id, url: `https://github.com/owner/${id}`, status, messages: [],
    created_at: '2026-11-09', report: { summary: 'Review', findings: [], limitations: [] } };
}

async function harness() {
  const elements = new Map();
  const get = (id) => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  const timers = new Map();
  let timerId = 0;
  let fetchHandler = async (url) => {
    const defaults = { '/api/scans': { scans: [] }, '/api/models': { models: [] },
      '/api/keys': { keys: [] }, '/api/providers': { providers: [] } };
    return response(defaults[url] || job('A'));
  };
  const storage = new Map();
  const context = vm.createContext({
    document: { getElementById: get, createElement: (tag) => new Element(tag),
      querySelectorAll: () => [], addEventListener() {}, activeElement: new Element('input') },
    location: { hash: '#token=fixture-token', pathname: '/' },
    history: { replaceState() {} },
    sessionStorage: { setItem: (key, value) => storage.set(key, value), getItem: (key) => storage.get(key) },
    Option: class extends Element { constructor(label, value) { super('option'); this.textContent = label; this.value = value; } },
    fetch: (...args) => fetchHandler(...args),
    setTimeout: (callback, delay) => { timers.set(++timerId, { callback, delay }); return timerId; },
    clearTimeout: (id) => timers.delete(id),
    URL, URLSearchParams, console,
  });
  const source = fs.readFileSync(path.join(__dirname, '../public/app.js'), 'utf8');
  vm.runInContext(source, context);
  await flush();
  return { get, timers, context, run: (code) => vm.runInContext(code, context),
    setFetch: (handler) => { fetchHandler = handler; } };
}

async function flush() {
  for (let index = 0; index < 12; index++) await Promise.resolve();
}

test('old history response cannot restart polling after New Scan', async () => {
  const app = await harness();
  const history = deferred();
  app.setFetch(async (url) => url === '/api/scans' ? history.promise : response(job('A')));
  const pending = app.run("openScan('A')");
  await flush();
  app.run('showWelcome()');
  history.resolve(response({ scans: [job('A')] }));
  await pending;
  assert.equal(app.run('currentId'), null);
  assert.equal([...app.timers.values()].filter((timer) => timer.delay === 3000).length, 0);
});

test('scan creation cannot steal a newer view', async () => {
  const app = await harness();
  const scan = deferred();
  app.setFetch(async (url, options) => options.method === 'POST' ? scan.promise : response({ scans: [] }));
  app.get('repoUrl').value = 'https://github.com/owner/A';
  const pending = app.get('scanForm').listeners.submit({ preventDefault() {} });
  app.run('showWelcome()');
  scan.resolve(response(job('A')));
  await pending;
  assert.equal(app.run('currentId'), null);
});

for (const succeeds of [true, false]) {
  test(`chat captures model/key and preserves a newer draft on ${succeeds ? 'success' : 'failure'}`, async () => {
    const app = await harness();
    const scan = deferred();
    let sent;
    app.run("currentId = 'A'; viewGeneration = 1");
    app.get('chatInput').value = 'first question';
    app.get('chatModel').value = 'openrouter|vendor/model:free';
    app.get('chatKey').value = 'original-key';
    app.setFetch(async (url, options) => {
      if (options.method !== 'POST') return scan.promise;
      sent = JSON.parse(options.body);
      return response(succeeds ? { messages: [{ role: 'assistant', content: 'old answer' }] } : { error: 'fixture error' }, succeeds);
    });
    const pending = app.get('chatForm').listeners.submit({ preventDefault() {} });
    app.run('showWelcome()');
    app.get('chatInput').value = 'new draft';
    app.get('chatModel').value = 'different-model';
    app.get('chatKey').value = 'different-key';
    scan.resolve(response(job('A', 'complete')));
    await pending;
    assert.equal(sent.model, 'openrouter|vendor/model:free');
    assert.equal(sent.key_alias, 'original-key');
    assert.equal(app.get('chatInput').value, 'new draft');
    assert.equal(app.run('pendingChats.size'), 0);
  });
}

test('pasted free model stays exact with floor box checked', async () => {
  const app = await harness();
  const id = 'nvidia/nemotron-3-ultra-550b-a55b:free';
  app.get('modelProvider').value = 'openrouter';
  app.get('modelId').value = id;
  app.get('floorMode').checked = true;
  let sent;
  app.setFetch(async (url, options) => {
    sent = JSON.parse(options.body);
    return response({ models: [`openrouter|${sent.id}`] });
  });
  await app.get('modelForm').listeners.submit({ preventDefault() {} });
  assert.equal(sent.id, id);
});
