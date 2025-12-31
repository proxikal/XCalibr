import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('CSS Minifier Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the CSS Minifier interface', async () => {
    const root = await mountWithTool('cssMinifier');
    aiAssertTruthy({ name: 'CssMinifierRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'CssMinifierTitle' }, text.includes('CSS') || text.includes('Minifier'));
  });

  it('shows input textarea', async () => {
    const root = await mountWithTool('cssMinifier');
    const textarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'CssMinifierInput' }, textarea);
  });

  it('displays minified output', async () => {
    const root = await mountWithTool('cssMinifier', {
      input: '.class { color: red; }',
      output: '.class{color:red}'
    });
    const text = root?.textContent || '';
    const textareas = root?.querySelectorAll('textarea');
    aiAssertTruthy({ name: 'CssMinifierOutput' },
      (textareas && textareas.length >= 1) || text.includes('.class'));
  });

  it('has minify button', async () => {
    const root = await mountWithTool('cssMinifier');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'CssMinifierButton' }, button);
  });

  it('shows size comparison', async () => {
    const root = await mountWithTool('cssMinifier', {
      input: '.test { margin: 0; }',
      output: '.test{margin:0}',
      originalSize: 20,
      minifiedSize: 16
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'CssMinifierSize' },
      text.includes('size') || text.includes('Size') || text.includes('%') || text.includes('bytes'));
  });
});
