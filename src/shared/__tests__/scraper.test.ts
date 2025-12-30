import { describe, it } from 'vitest';
import { aiAssertEqual, aiAssertIncludes, aiAssertTruthy } from '../../test-utils/aiAssert';
import { generateCssSelector, generateXPath, normalizeScrapers } from '../scraper';

describe('scraper selectors', () => {
  it('builds a css selector that resolves to the element', () => {
    document.body.innerHTML = `
      <div class="card">
        <p>first</p>
        <p class="target">second</p>
      </div>
    `;
    const target = document.querySelector('.target') as Element;
    const selector = generateCssSelector(target);
    const resolved = document.querySelector(selector);
    aiAssertEqual(
      { name: 'generateCssSelector', input: { selector } },
      resolved,
      target
    );
  });

  it('builds an xpath selector for id elements', () => {
    document.body.innerHTML = `<div id="main"><span>ok</span></div>`;
    const target = document.getElementById('main') as Element;
    const xpath = generateXPath(target);
    aiAssertIncludes(
      { name: 'generateXPath', input: { xpath } },
      xpath,
      '//*[@id="main"]'
    );
  });
});

describe('scraper storage normalization', () => {
  it('filters invalid entries from storage', () => {
    const normalized = normalizeScrapers([
      null,
      { id: 'a', name: 'Test', fields: [] },
      { id: 'b', name: 'Bad', fields: [{ id: 'f' }] }
    ]);
    aiAssertTruthy(
      { name: 'normalizeScrapers', input: { normalized } },
      normalized.length === 2
    );
    aiAssertEqual(
      { name: 'normalizeScrapers', state: normalized },
      normalized[0].id,
      'a'
    );
  });
});
