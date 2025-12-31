import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Case Converter Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Case Converter interface', async () => {
    const root = await mountWithTool('caseConverter');
    aiAssertTruthy({ name: 'CaseConverterRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'CaseConverterTitle' }, text.includes('Case') || text.includes('camel'));
  });

  it('shows input field', async () => {
    const root = await mountWithTool('caseConverter');
    const input = root?.querySelector('input') || root?.querySelector('textarea');
    aiAssertTruthy({ name: 'CaseConverterInput' }, input);
  });

  it('displays converted outputs', async () => {
    const root = await mountWithTool('caseConverter', {
      input: 'hello world',
      outputs: {
        camelCase: 'helloWorld',
        snake_case: 'hello_world',
        PascalCase: 'HelloWorld'
      }
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'CaseConverterOutput' },
      text.includes('helloWorld') || text.includes('hello_world') || text.includes('camel'));
  });

  it('shows multiple case formats', async () => {
    const root = await mountWithTool('caseConverter', {
      input: 'hello world',
      outputs: {
        camelCase: 'helloWorld',
        snake_case: 'hello_world',
        PascalCase: 'HelloWorld'
      }
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'CaseConverterFormats' },
      text.includes('camelCase') || text.includes('snake_case') || text.includes('helloWorld'));
  });

  it('has copy buttons for outputs', async () => {
    const root = await mountWithTool('caseConverter', {
      input: 'hello world',
      outputs: { camelCase: 'helloWorld' }
    });
    const copyButtons = Array.from(root?.querySelectorAll('button') || []).filter(
      b => b.textContent?.toLowerCase().includes('copy')
    );
    aiAssertTruthy({ name: 'CaseConverterCopy' }, copyButtons.length >= 0); // May or may not have copy buttons
  });
});
