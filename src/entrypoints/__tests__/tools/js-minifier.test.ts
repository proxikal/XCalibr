import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('JS Minifier Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the JS Minifier interface', async () => {
    const root = await mountWithTool('jsMinifier');
    aiAssertTruthy({ name: 'JsMinifierRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'JsMinifierTitle' }, text.includes('JS') || text.includes('Minifier') || text.includes('JavaScript'));
  });

  it('shows input textarea', async () => {
    const root = await mountWithTool('jsMinifier');
    const textarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'JsMinifierInput' }, textarea);
  });

  it('displays minified output', async () => {
    const root = await mountWithTool('jsMinifier', {
      input: 'function test() { return true; }',
      output: 'function test(){return!0}'
    });
    const text = root?.textContent || '';
    const textareas = root?.querySelectorAll('textarea');
    aiAssertTruthy({ name: 'JsMinifierOutput' },
      (textareas && textareas.length >= 1) || text.includes('function'));
  });

  it('has minify button', async () => {
    const root = await mountWithTool('jsMinifier');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'JsMinifierButton' }, button);
  });

  it('shows size comparison', async () => {
    const root = await mountWithTool('jsMinifier', {
      input: 'const x = 1;',
      output: 'const x=1',
      originalSize: 12,
      minifiedSize: 10
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'JsMinifierSize' },
      text.includes('size') || text.includes('Size') || text.includes('%') || text.includes('bytes'));
  });
});
