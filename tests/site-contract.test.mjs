import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

const root = new URL('../', import.meta.url);
const pagePaths = {
  en: new URL('index.html', root),
  zh: new URL('zh/index.html', root),
};

const expected = {
  en: {
    lang: 'en',
    canonical: 'https://agent.rustscript.org/',
    alternate: 'https://agent.rustscript.org/zh/',
    languageHref: '/zh/',
    stylesheet: 'styles.css',
    script: 'script.js',
  },
  zh: {
    lang: 'zh-CN',
    canonical: 'https://agent.rustscript.org/zh/',
    alternate: 'https://agent.rustscript.org/',
    languageHref: '/',
    stylesheet: '../styles.css',
    script: '../script.js',
  },
};

const readPages = async () => Object.fromEntries(await Promise.all(
  Object.entries(pagePaths).map(async ([locale, path]) => [locale, await readFile(path, 'utf8')]),
));

const getAttribute = (tag, name) => tag.match(new RegExp(`\\b${name}="([^"]+)"`, 'i'))?.[1];
const findTag = (html, tagName, name, value) => (
  [...html.matchAll(new RegExp(`<${tagName}\\b[^>]*>`, 'gi'))]
    .map(match => match[0])
    .find(tag => getAttribute(tag, name) === value)
);

const hrefs = html => [...html.matchAll(/<a\b[^>]*\bhref="([^"]+)"/gi)].map(match => match[1]);
const ids = html => new Set([...html.matchAll(/\bid="([^"]+)"/gi)].map(match => match[1]));
const dataValues = (html, name) => [...html.matchAll(new RegExp(`\\bdata-${name}="([^"]+)"`, 'gi'))].map(match => match[1]);
const classCount = (html, className) => [...html.matchAll(/\bclass="([^"]+)"/gi)]
  .filter(match => match[1].split(/\s+/).includes(className)).length;
const externalHrefs = html => hrefs(html).filter(href => href.startsWith('https://')).sort();

for (const [locale, path] of Object.entries(pagePaths)) {
  test(`${locale} route has localized metadata and reciprocal language discovery`, async () => {
    const html = await readFile(path, 'utf8');
    const config = expected[locale];

    assert.equal(getAttribute(findTag(html, 'html', 'lang', config.lang) ?? '', 'lang'), config.lang);
    assert.equal(getAttribute(findTag(html, 'link', 'rel', 'canonical') ?? '', 'href'), config.canonical);
    assert.equal(getAttribute(findTag(html, 'link', 'hreflang', 'en') ?? '', 'href'), 'https://agent.rustscript.org/');
    assert.equal(getAttribute(findTag(html, 'link', 'hreflang', 'zh-CN') ?? '', 'href'), 'https://agent.rustscript.org/zh/');
    assert.equal(getAttribute(findTag(html, 'meta', 'property', 'og:url') ?? '', 'content'), config.canonical);
    assert.equal(getAttribute(findTag(html, 'link', 'rel', 'stylesheet') ?? '', 'href'), config.stylesheet);
    assert.equal(getAttribute(findTag(html, 'script', 'src', config.script) ?? '', 'src'), config.script);
    assert.match(html, /<title>[^<]+<\/title>/);
    assert.match(html, /<meta\b[^>]*name="description"[^>]*content="[^"]+"/i);
    assert.match(html, new RegExp(`<a\\b[^>]*data-language-link[^>]*href="${config.languageHref}"`));
  });
}

test('both documents expose the same complete three-pillar content contract', async () => {
  const pages = await readPages();
  const requiredIds = ['sandbox-gap', 'pillars', 'effect-sandbox', 'tool-graph'];

  for (const [locale, html] of Object.entries(pages)) {
    const pageIds = ids(html);
    for (const id of requiredIds) assert.ok(pageIds.has(id), `${locale} is missing #${id}`);
    for (const label of ['Typed Contracts', 'Effect Sandbox', 'Tool Graph']) {
      assert.match(html, new RegExp(label, 'i'), `${locale} is missing ${label}`);
    }
    assert.match(html, /write_file\(&quot;race\.txt&quot;, &quot;first&quot;\)|write_file\("race\.txt", "first"\)/);
    assert.match(html, /Graph A/i);
    assert.match(html, /Graph B/i);
    assert.match(html, /Run α/);
    assert.match(html, /Run β/);
    assert.match(html, /Run γ/);
    assert.match(html, /arbitrary external|任意外部系统/i);
    assert.doesNotMatch(html, /Result\s*&lt;\s*Option|Result\s*<\s*Option/);
    assert.deepEqual(dataValues(html, 'stage'), ['contracts', 'effects', 'graph']);
    assert.deepEqual(dataValues(html, 'graph-state'), ['upgrade', 'rollback']);
  }

  assert.deepEqual([...ids(pages.en)].filter(id => requiredIds.includes(id)), requiredIds);
  assert.deepEqual([...ids(pages.zh)].filter(id => requiredIds.includes(id)), requiredIds);
  assert.deepEqual(externalHrefs(pages.zh), externalHrefs(pages.en));
});

test('both routes keep static navigation and all enhanced states in the document', async () => {
  const pages = await readPages();
  for (const [locale, html] of Object.entries(pages)) {
    for (const target of ['#sandbox-gap', '#pillars', '#effect-sandbox', '#tool-graph']) {
      assert.ok(hrefs(html).includes(target), `${locale} cannot navigate to ${target} without JavaScript`);
    }
    assert.equal(classCount(html, 'stage-panel'), 3);
    assert.equal(classCount(html, 'graph-state-panel'), 2);
  }
});

test('graph controls expose explicit state and a live announcement in both documents', async () => {
  const pages = await readPages();
  for (const [locale, html] of Object.entries(pages)) {
    const controls = [...html.matchAll(/<button\b[^>]*data-graph-state="(upgrade|rollback)"[^>]*>/gi)];
    assert.deepEqual(controls.map(match => match[1]), ['upgrade', 'rollback']);
    assert.equal(getAttribute(controls[0][0], 'type'), 'button', `${locale} upgrade control needs button semantics`);
    assert.equal(getAttribute(controls[0][0], 'aria-pressed'), 'true');
    assert.equal(getAttribute(controls[1][0], 'aria-pressed'), 'false');
    assert.ok(getAttribute(controls[0][0], 'data-graph-announcement'));
    assert.ok(getAttribute(controls[1][0], 'data-graph-announcement'));
    const status = findTag(html, 'p', 'id', 'graph-status');
    assert.equal(getAttribute(status ?? '', 'role'), 'status');
    assert.equal(getAttribute(status ?? '', 'aria-live'), 'polite');
  }
});

class FakeElement {
  constructor(dataset = {}) {
    this.dataset = dataset;
    this.attributes = new Map();
    this.hidden = false;
    this.textContent = '';
    this.value = '';
    this.style = { setProperty() {} };
    this.children = new Map();
    this.listeners = new Map();
    this.classList = {
      values: new Set(),
      add: value => this.classList.values.add(value),
      remove: value => this.classList.values.delete(value),
      toggle: (value, force) => {
        const enabled = force ?? !this.classList.values.has(value);
        if (enabled) this.classList.values.add(value);
        else this.classList.values.delete(value);
      },
    };
  }

  addEventListener(type, listener) { this.listeners.set(type, listener); }
  querySelector(selector) { return this.children.get(selector) ?? null; }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  click() { this.listeners.get('click')?.({ preventDefault() {} }); }
}

test('shared script changes graph state without moving existing run pins', async () => {
  const source = await readFile(new URL('script.js', root), 'utf8');
  const upgrade = new FakeElement({
    graphState: 'upgrade',
    graphAnnouncement: 'Run α stays on Graph A; new Run β captures Graph B.',
  });
  const rollback = new FakeElement({
    graphState: 'rollback',
    graphAnnouncement: 'Run α and Run β keep their pins; new Run γ captures Graph A.',
  });
  const upgradePanel = new FakeElement({ graphPanel: 'upgrade' });
  const rollbackPanel = new FakeElement({ graphPanel: 'rollback' });
  const status = new FakeElement();
  const rootElement = new FakeElement();
  rootElement.classList.values.add('no-js');

  const selectorLists = new Map([
    ['[data-reveal]', []],
    ['.stage-tab[data-stage]', []],
    ['.stage-panel', []],
    ['.event-row', []],
    ['.graph-state-control[data-graph-state]', [upgrade, rollback]],
    ['.graph-state-panel[data-graph-panel]', [upgradePanel, rollbackPanel]],
  ]);
  const selectors = new Map([['#graph-status', status]]);
  const media = { matches: false, addEventListener() {} };
  const document = {
    documentElement: rootElement,
    hidden: false,
    querySelectorAll: selector => selectorLists.get(selector) ?? [],
    querySelector: selector => selectors.get(selector) ?? null,
    addEventListener() {},
  };
  const window = {
    matchMedia: () => media,
    addEventListener() {},
    clearInterval() {},
    setInterval() { return 1; },
    requestAnimationFrame() { return 1; },
    innerHeight: 900,
  };
  const context = vm.createContext({ document, window, performance: { now: () => 0 } });

  vm.runInContext(source, context);
  rollback.click();

  assert.equal(upgrade.getAttribute('aria-pressed'), 'false');
  assert.equal(rollback.getAttribute('aria-pressed'), 'true');
  assert.equal(upgradePanel.hidden, true);
  assert.equal(rollbackPanel.hidden, false);
  assert.equal(status.textContent, rollback.dataset.graphAnnouncement);
  assert.match(status.textContent, /Run α/);
  assert.match(status.textContent, /Run β/);
  assert.match(status.textContent, /Run γ/);
});

test('social card carries the three-pillar position at exactly 1200 by 630', async () => {
  const svg = await readFile(new URL('og-image.svg', root), 'utf8');
  const png = await readFile(new URL('og-image.png', root));

  assert.match(svg, /width="1200" height="630"/);
  assert.match(svg, /Beyond the agent sandbox/i);
  assert.match(svg, /Typed Contracts/);
  assert.match(svg, /Effect Sandbox/);
  assert.match(svg, /Tool Graph/);
  assert.equal(png.toString('ascii', 1, 4), 'PNG');
  assert.equal(png.readUInt32BE(16), 1200);
  assert.equal(png.readUInt32BE(20), 630);
});

test('event replay reports a retained head conflict instead of an effect reversal', async () => {
  const source = await readFile(new URL('script.js', root), 'utf8');
  const rows = Array.from({ length: 5 }, () => new FakeElement());
  const terminalName = new FakeElement();
  const terminalState = new FakeElement();
  rows[4].children.set('b', terminalName);
  rows[4].children.set('span', terminalState);
  const eventConsole = new FakeElement();
  const replay = new FakeElement();
  const outcome = new FakeElement();
  const cursor = new FakeElement();
  const cursorOutput = new FakeElement();
  const streamState = new FakeElement();
  const rootElement = new FakeElement();

  const selectorLists = new Map([
    ['[data-reveal]', []],
    ['.stage-tab[data-stage]', []],
    ['.stage-panel', []],
    ['.event-row', rows],
    ['.graph-state-control[data-graph-state]', []],
    ['.graph-state-panel[data-graph-panel]', []],
  ]);
  const selectors = new Map([
    ['.event-console', eventConsole],
    ['#event-replay', replay],
    ['#event-outcome', outcome],
    ['#replay-cursor', cursor],
    ['#cursor-output', cursorOutput],
    ['#stream-state', streamState],
  ]);
  const media = { matches: true, addEventListener() {} };
  const document = {
    documentElement: rootElement,
    hidden: false,
    querySelectorAll: selector => selectorLists.get(selector) ?? [],
    querySelector: selector => selectors.get(selector) ?? null,
    addEventListener() {},
  };
  const window = {
    matchMedia: () => media,
    addEventListener() {},
    clearInterval() {},
    setInterval() { return 1; },
    requestAnimationFrame() { return 1; },
    innerHeight: 900,
  };

  vm.runInContext(source, vm.createContext({ document, window, performance: { now: () => 0 } }));
  outcome.click();
  replay.click();

  assert.equal(outcome.textContent, 'Commit');
  assert.equal(terminalName.textContent, 'effect.head_conflict');
  assert.equal(terminalState.textContent, 'candidate retained');
  assert.equal(streamState.textContent, 'HEAD CONFLICT');
});
