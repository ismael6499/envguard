'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const EN_PATH = path.join(ROOT, 'src', 'i18n', 'locales', 'en.json');
const ES_PATH = path.join(ROOT, 'src', 'i18n', 'locales', 'es.json');
const HTML_PATH = path.join(ROOT, 'src', 'ui', 'index.html');
const APP_JS_PATH = path.join(ROOT, 'src', 'ui', 'app.js');

function parseHtmlVirtualDom(html) {
  const nodes = [];
  const stack = [{ tag: 'root', children: nodes }];
  const voidTags = new Set(['meta', 'link', 'input', 'hr', 'br', 'img']);
  const tokenRx = /<!--[\s\S]*?-->|<\/([a-zA-Z0-9-]+)>|<([a-zA-Z0-9-]+)([^>]*?)(\/?)>|([^<]+)/g;
  let match;
  while ((match = tokenRx.exec(html)) !== null) {
    if (match[1]) {
      const tag = match[1].toLowerCase();
      while (stack.length > 1 && stack[stack.length - 1].tag !== tag) {
        stack.pop();
      }
      if (stack.length > 1) stack.pop();
    } else if (match[2]) {
      const tag = match[2].toLowerCase();
      const rawAttrs = match[3] || '';
      const selfClose = Boolean(match[4]) || voidTags.has(tag);
      const attrs = {};
      const attrRx = /([a-zA-Z0-9_-]+)(?:="([^"]*)")?/g;
      let am;
      while ((am = attrRx.exec(rawAttrs)) !== null) {
        attrs[am[1]] = am[2] !== undefined ? am[2] : true;
      }
      const node = { tag, attrs, children: [], text: '' };
      stack[stack.length - 1].children.push(node);
      if (!selfClose) stack.push(node);
    } else if (match[5]) {
      const text = match[5].replace(/\s+/g, ' ').trim();
      if (text && stack.length > 0) {
        stack[stack.length - 1].text += (stack[stack.length - 1].text ? ' ' : '') + text;
      }
    }
  }
  return nodes;
}

function walkTree(nodes, cb) {
  for (const n of nodes) {
    cb(n);
    if (n.children && n.children.length > 0) walkTree(n.children, cb);
  }
}

function runAudit() {
  const en = JSON.parse(fs.readFileSync(EN_PATH, 'utf8'));
  const es = JSON.parse(fs.readFileSync(ES_PATH, 'utf8'));
  const html = fs.readFileSync(HTML_PATH, 'utf8');
  const appJs = fs.readFileSync(APP_JS_PATH, 'utf8');

  const enKeys = Object.keys(en).sort();
  const esKeys = Object.keys(es).sort();

  const missingInEs = enKeys.filter((k) => !Object.prototype.hasOwnProperty.call(es, k));
  const missingInEn = esKeys.filter((k) => !Object.prototype.hasOwnProperty.call(en, k));

  assert.strictEqual(missingInEs.length, 0, `Keys missing in es.json: ${missingInEs.join(', ')}`);
  assert.strictEqual(missingInEn.length, 0, `Keys missing in en.json: ${missingInEn.join(', ')}`);

  for (const k of enKeys) {
    assert(String(en[k]).trim().length > 0, `Empty en.json value for ${k}`);
    assert(String(es[k]).trim().length > 0, `Empty es.json value for ${k}`);
  }

  const vdom = parseHtmlVirtualDom(html);
  const textTags = new Set(['h1', 'h2', 'h3', 'h4', 'button', 'label', 'option', 'th', 'p', 'title']);
  const dynamicIds = new Set(['activeEnvHeader', 'historyModalTitle', 'gitHelperBanner']);
  let dataI18nCount = 0;
  let checkedElements = 0;
  const unknownHtmlKeys = [];
  const hardcodedElements = [];

  walkTree(vdom, (node) => {
    checkedElements += 1;
    if (node.attrs['data-i18n']) {
      dataI18nCount += 1;
      const key = node.attrs['data-i18n'];
      if (!en[key] || !es[key]) unknownHtmlKeys.push(key);
    }
    if (node.attrs['data-i18n-placeholder']) {
      dataI18nCount += 1;
      const key = node.attrs['data-i18n-placeholder'];
      if (!en[key] || !es[key]) unknownHtmlKeys.push(key);
    }
    if (textTags.has(node.tag) && node.text && !node.attrs['data-i18n'] && !dynamicIds.has(node.attrs.id)) {
      hardcodedElements.push(`<${node.tag}> "${node.text}"`);
    }
  });

  assert.strictEqual(unknownHtmlKeys.length, 0, `Unknown data-i18n keys in HTML: ${unknownHtmlKeys.join(', ')}`);
  assert.strictEqual(hardcodedElements.length, 0, `Hardcoded text in HTML: ${hardcodedElements.join('; ')}`);

  // Verify all t('...') calls in app.js
  const tCallRx = /\bt\(\s*['"]([a-zA-Z0-9_]+)['"]/g;
  const jsKeys = new Set();
  let m;
  while ((m = tCallRx.exec(appJs)) !== null) {
    jsKeys.add(m[1]);
  }
  const unknownJsKeys = Array.from(jsKeys).filter((k) => !en[k] || !es[k]);
  assert.strictEqual(unknownJsKeys.length, 0, `Unknown t('...') keys in app.js: ${unknownJsKeys.join(', ')}`);

  console.log('=== EnvGuard UI & i18n Virtual DOM Audit ===');
  console.log(`Locale keys (EN & ES parity): ${enKeys.length} / ${esKeys.length} (100% match)`);
  console.log(`Virtual DOM elements scanned: ${checkedElements}`);
  console.log(`Localized HTML bindings checked: ${dataI18nCount}`);
  console.log(`Dynamic JS t(...) keys verified: ${jsKeys.size}`);
  console.log('Hardcoded text violations: 0');
  console.log('RESULT: PASS');
}

runAudit();
