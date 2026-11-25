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
const idList = html => [...html.matchAll(/\bid="([^"]+)"/gi)].map(match => match[1]);
const tags = html => [...html.matchAll(/<([a-z][\w-]*)\b[^>]*>/gi)].map(match => ({
  name: match[1].toLowerCase(),
  source: match[0],
}));
const dataHookInventory = html => tags(html).flatMap(({ name, source }) => {
  const id = getAttribute(source, 'id') ?? '';
  const classes = (getAttribute(source, 'class') ?? '').split(/\s+/).filter(Boolean).sort().join('.');
  return [...source.matchAll(/\bdata-([\w-]+)(?:="([^"]*)")?/gi)].map(match => {
    const value = ['graph-announcement', 'locale'].includes(match[1]) ? '<localized>' : (match[2] ?? '<present>');
    return `${name}#${id}.${classes}|${match[1]}=${value}`;
  });
}).sort();
const textContent = html => html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();

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

  const pillarLabels = {
    en: ['Typed Contracts', 'Effect Sandbox', 'Tool Graph'],
    zh: ['类型化契约', '作用沙箱', '工具图谱'],
  };

  for (const [locale, html] of Object.entries(pages)) {
    const pageIds = ids(html);
    for (const id of requiredIds) assert.ok(pageIds.has(id), `${locale} is missing #${id}`);
    for (const label of pillarLabels[locale]) {
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

test('both documents have complete normalized ID and interaction-hook parity', async () => {
  const pages = await readPages();
  assert.deepEqual(idList(pages.zh), idList(pages.en));
  assert.equal(new Set(idList(pages.en)).size, idList(pages.en).length, 'English IDs must be unique');
  assert.equal(new Set(idList(pages.zh)).size, idList(pages.zh).length, 'Chinese IDs must be unique');
  assert.deepEqual(dataHookInventory(pages.zh), dataHookInventory(pages.en));

  for (const [locale, html] of Object.entries(pages)) {
    const pageIds = ids(html);
    for (const { source } of tags(html)) {
      for (const attribute of ['aria-controls', 'aria-labelledby']) {
        const references = (getAttribute(source, attribute) ?? '').split(/\s+/).filter(Boolean);
        for (const reference of references) {
          assert.ok(pageIds.has(reference), `${locale} ${attribute} points to missing #${reference}`);
        }
      }
      const href = getAttribute(source, 'href');
      if (href?.startsWith('#')) {
        assert.ok(pageIds.has(href.slice(1)), `${locale} href points to missing ${href}`);
      }
    }
    assert.deepEqual(dataValues(html, 'step'), ['0', '1', '2', '3', '4']);
    assert.deepEqual(
      [...html.matchAll(/<div\b[^>]*class="[^"]*\bevent-row\b[^"]*"[^>]*>[\s\S]*?<b>([^<]+)<\/b>/gi)].map(match => match[1]),
      ['run.started', 'tool.requested', 'tool.started', 'tool.output', 'tool.completed'],
      `${locale} must show the emitted success sequence`,
    );
  }
});

test('event demo uses only registered runtime events and the real conflict error', async () => {
  const pages = await readPages();
  const script = await readFile(new URL('script.js', root), 'utf8');
  const combined = `${pages.en}\n${pages.zh}\n${script}`;
  for (const invented of [
    'run.admitted',
    'effect.prepared',
    'receipt.pending',
    'effect.committed',
    'result.readback',
    'effect.head_checked',
    'effect.head_conflict',
  ]) {
    assert.doesNotMatch(combined, new RegExp(invented.replace('.', '\\.'), 'i'));
  }
  assert.match(combined, /effect_head_conflict/);
  assert.match(combined, /tool\.failed/);
});

test('Chinese page localizes explanatory labels and enhanced controls', async () => {
  const html = await readFile(pagePaths.zh, 'utf8');
  const visibleText = textContent(html);
  for (const phrase of [
    'typed orchestration',
    'resource authority',
    'private managed view',
    'receipt + readback',
    'immutable graph pin',
    'new generation',
    '>Replay<',
    '>Conflict<',
    'replay cursor',
    'append-only event order',
    'Run α captured A',
    'Run β captures B',
    'Run β stays on B',
    'new Run γ captures A',
  ]) {
    assert.doesNotMatch(phrase.startsWith('>') ? html : visibleText, new RegExp(phrase, 'i'), `Chinese copy leaked: ${phrase}`);
  }
  assert.match(html, />重放</);
  assert.match(html, />显示冲突</);
  assert.match(html, />RustScript 博客/);
});

test('no-JavaScript mode hides inert enhanced controls and retains static state links', async () => {
  const pages = await readPages();
  const css = await readFile(new URL('styles.css', root), 'utf8');
  assert.match(css, /\.no-js\s+\[data-enhanced-control\][^{]*\{[^}]*display\s*:\s*none/);
  for (const [locale, html] of Object.entries(pages)) {
    const enhancedButtons = tags(html).filter(({ name, source }) => name === 'button' && /\bdata-enhanced-control\b/i.test(source));
    assert.equal(enhancedButtons.length, 5, `${locale} should mark menu, replay, outcome, and both graph control buttons`);
    assert.equal(classCount(html, 'graph-state-panel'), 2, `${locale} retains both graph states`);
    assert.equal(classCount(html, 'stage-panel'), 3, `${locale} retains all pillar states`);
    for (const stage of ['contracts', 'effects', 'graph']) {
      const tab = tags(html).find(({ name, source }) => name === 'a' && getAttribute(source, 'data-stage') === stage);
      assert.ok(tab, `${locale} keeps a static anchor for ${stage}`);
      assert.match(getAttribute(tab.source, 'href') ?? '', /^#panel-/);
    }
  }
});

test('minimum supported viewport is not forced wider by the body', async () => {
  const css = await readFile(new URL('styles.css', root), 'utf8');
  assert.doesNotMatch(css, /body\s*\{[^}]*\bmin-width\s*:\s*320px/i);
});

test('CTA names the generic RustScript blog and sitemap lists both language routes', async () => {
  const pages = await readPages();
  assert.match(pages.en, /href="https:\/\/rustscript\.org\/blog">RustScript blog/);
  assert.match(pages.zh, /href="https:\/\/rustscript\.org\/blog">RustScript 博客/);
  const sitemap = await readFile(new URL('sitemap.xml', root), 'utf8');
  assert.match(sitemap, /https:\/\/agent\.rustscript\.org\/zh\//);
  assert.match(sitemap, /hreflang="en"/);
  assert.match(sitemap, /hreflang="zh-CN"/);
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

  addEventListener(type, listener) {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }
  querySelector(selector) { return this.children.get(selector) ?? null; }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  dispatch(type, event = {}) {
    for (const listener of this.listeners.get(type) ?? []) {
      listener({ preventDefault() {}, target: this, ...event });
    }
  }
  click() { this.dispatch('click'); }
  focus() { this.focused = true; }
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

test('pillar tabs support complete roving-keyboard navigation', async () => {
  const source = await readFile(new URL('script.js', root), 'utf8');
  const stages = ['contracts', 'effects', 'graph'];
  const tabs = stages.map(stage => {
    const tab = new FakeElement({ stage });
    tab.id = `tab-${stage}`;
    tab.setAttribute('href', `#panel-${stage}`);
    return tab;
  });
  const panels = stages.map(stage => {
    const panel = new FakeElement();
    panel.id = `panel-${stage}`;
    return panel;
  });
  const rootElement = new FakeElement();
  const selectorLists = new Map([
    ['[data-reveal]', []],
    ['.stage-tab[data-stage]', tabs],
    ['.stage-panel', panels],
    ['.event-row', []],
    ['.graph-state-control[data-graph-state]', []],
    ['.graph-state-panel[data-graph-panel]', []],
  ]);
  const tablist = new FakeElement();
  const document = {
    documentElement: rootElement,
    hidden: false,
    querySelectorAll: selector => selectorLists.get(selector) ?? [],
    querySelector: selector => selector === '.stage-tabs' ? tablist : null,
    addEventListener() {},
  };
  const media = { matches: false, addEventListener() {} };
  const window = {
    matchMedia: () => media,
    addEventListener() {},
    clearInterval() {},
    setInterval() { return 1; },
    requestAnimationFrame() { return 1; },
    innerHeight: 900,
  };

  vm.runInContext(source, vm.createContext({ document, window, performance: { now: () => 0 } }));
  tabs[0].dispatch('keydown', { key: 'ArrowDown' });
  assert.equal(tabs[1].getAttribute('aria-selected'), 'true');
  assert.equal(tabs[1].focused, true);
  tabs[1].dispatch('keydown', { key: 'End' });
  assert.equal(tabs[2].getAttribute('aria-selected'), 'true');
  tabs[2].dispatch('keydown', { key: 'Home' });
  assert.equal(tabs[0].getAttribute('aria-selected'), 'true');
  tabs[0].dispatch('keydown', { key: 'ArrowUp' });
  assert.equal(tabs[2].getAttribute('aria-selected'), 'true');
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

test('event replay localizes every commit and conflict announcement and uses actual events', async () => {
  const source = await readFile(new URL('script.js', root), 'utf8');
  const cases = {
    en: {
      lang: 'en',
      outcomeCommit: 'Show commit',
      commit: [
        'Commit replay 1 of 5: run started.',
        'Commit replay 2 of 5: write_file requested.',
        'Commit replay 3 of 5: private managed view active.',
        'Commit replay 4 of 5: tool.output reports committed publication.',
        'Commit replay 5 of 5: tool.completed; receipt fx_7a29 read back.',
      ],
      conflict: [
        'Conflict replay 1 of 5: run started.',
        'Conflict replay 2 of 5: write_file requested.',
        'Conflict replay 3 of 5: private managed view active.',
        'Conflict replay 4 of 5: tool.output reports conflict; candidate retained.',
        'Conflict replay 5 of 5: tool.failed with effect_head_conflict.',
      ],
      decisionState: 'status: conflict',
    },
    zh: {
      lang: 'zh-CN',
      outcomeCommit: '显示提交',
      commit: [
        '提交重放 1/5：运行已开始。',
        '提交重放 2/5：已请求 write_file。',
        '提交重放 3/5：私有受管视图已启用。',
        '提交重放 4/5：tool.output 报告发布已提交。',
        '提交重放 5/5：tool.completed；已读回收据 fx_7a29。',
      ],
      conflict: [
        '冲突重放 1/5：运行已开始。',
        '冲突重放 2/5：已请求 write_file。',
        '冲突重放 3/5：私有受管视图已启用。',
        '冲突重放 4/5：tool.output 报告冲突；候选内容已保留。',
        '冲突重放 5/5：tool.failed，错误为 effect_head_conflict。',
      ],
      decisionState: '状态：冲突',
    },
  };

  for (const [locale, expectedCase] of Object.entries(cases)) {
    const rows = Array.from({ length: 5 }, () => new FakeElement());
    const decisionName = new FakeElement();
    const decisionState = new FakeElement();
    const terminalName = new FakeElement();
    const terminalState = new FakeElement();
    rows[3].children.set('b', decisionName);
    rows[3].children.set('span', decisionState);
    rows[4].children.set('b', terminalName);
    rows[4].children.set('span', terminalState);
    const eventConsole = new FakeElement();
    const replay = new FakeElement();
    const outcome = new FakeElement();
    const cursor = new FakeElement();
    const cursorOutput = new FakeElement();
    const streamState = new FakeElement();
    const rootElement = new FakeElement();
    rootElement.lang = expectedCase.lang;
    let intervalCallback = null;

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
      setInterval(callback) { intervalCallback = callback; return 1; },
      requestAnimationFrame() { return 1; },
      innerHeight: 900,
    };

    vm.runInContext(source, vm.createContext({ document, window, performance: { now: () => 0 } }));
    replay.click();
    const commitAnnouncements = [streamState.textContent];
    for (let step = 1; step < rows.length; step += 1) {
      intervalCallback();
      commitAnnouncements.push(streamState.textContent);
    }
    assert.deepEqual(commitAnnouncements, expectedCase.commit, `${locale} commit announcements`);

    outcome.click();
    assert.equal(outcome.textContent, expectedCase.outcomeCommit);
    assert.equal(decisionName.textContent, 'tool.output');
    assert.equal(decisionState.textContent, expectedCase.decisionState);
    assert.equal(terminalName.textContent, 'tool.failed');
    assert.equal(terminalState.textContent, 'effect_head_conflict');
    replay.click();
    const conflictAnnouncements = [streamState.textContent];
    for (let step = 1; step < rows.length; step += 1) {
      intervalCallback();
      conflictAnnouncements.push(streamState.textContent);
    }
    assert.deepEqual(conflictAnnouncements, expectedCase.conflict, `${locale} conflict announcements`);
  }
});
