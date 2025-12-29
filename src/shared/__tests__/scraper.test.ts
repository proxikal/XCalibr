import { describe, expect, it } from 'vitest';
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
    expect(resolved).toBe(target);
  });

  it('builds an xpath selector for id elements', () => {
    document.body.innerHTML = `<div id="main"><span>ok</span></div>`;
    const target = document.getElementById('main') as Element;
    const xpath = generateXPath(target);
    expect(xpath).toContain('//*[@id="main"]');
  });
});

describe('scraper storage normalization', () => {
  it('filters invalid entries from storage', () => {
    const normalized = normalizeScrapers([
      null,
      { id: 'a', name: 'Test', fields: [] },
      { id: 'b', name: 'Bad', fields: [{ id: 'f' }] }
    ]);
    expect(normalized.length).toBe(2);
    expect(normalized[0].id).toBe('a');
  });
});
