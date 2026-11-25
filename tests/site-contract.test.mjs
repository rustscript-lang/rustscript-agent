import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

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
