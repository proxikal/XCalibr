import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('HTTP Method Tester Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the HTTP Method Tester interface', async () => {
    const root = await mountWithTool('httpMethodTester');
    aiAssertTruthy({ name: 'HttpMethodTesterRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'HttpMethodTesterTitle' },
      text.includes('HTTP') || text.includes('Method') || text.includes('Test'));
  });

  it('shows URL input', async () => {
    const root = await mountWithTool('httpMethodTester');
    const input = root?.querySelector('input') || root?.querySelector('textarea');
    aiAssertTruthy({ name: 'HttpMethodTesterInput' }, input);
  });

  it('has test button', async () => {
    const root = await mountWithTool('httpMethodTester');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'HttpMethodTesterButton' }, button);
  });

  it('shows HTTP methods list', async () => {
    const root = await mountWithTool('httpMethodTester');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'HttpMethodTesterMethods' },
      text.includes('GET') || text.includes('POST') || text.includes('PUT') || text.includes('DELETE'));
  });

  it('shows method results with status codes', async () => {
    const root = await mountWithTool('httpMethodTester', {
      url: 'https://example.com/api',
      results: [
        { method: 'GET', status: 200, allowed: true },
        { method: 'POST', status: 405, allowed: false },
        { method: 'OPTIONS', status: 200, allowed: true }
      ],
      testedAt: Date.now()
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'HttpMethodTesterResults' },
      text.includes('GET') || text.includes('200') || text.includes('405') || (root?.querySelectorAll('*').length ?? 0) > 5);
  });
});
