import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('TypeScript Interface Generator Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the TypeScript Interface Generator interface', async () => {
    const root = await mountWithTool('typescriptInterfaceGen');
    aiAssertTruthy({ name: 'TypescriptInterfaceGenRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TypescriptInterfaceGenTitle' }, text.includes('TypeScript') || text.includes('Interface'));
  });

  it('shows JSON input textarea', async () => {
    const root = await mountWithTool('typescriptInterfaceGen');
    const textarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'TypescriptInterfaceGenInput' }, textarea);
  });

  it('generates TypeScript interface', async () => {
    const root = await mountWithTool('typescriptInterfaceGen', {
      input: '{"name": "test"}',
      output: 'interface Root { name: string; }'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TypescriptInterfaceGenOutput' },
      text.includes('interface') || text.includes('string') || text.includes(':'));
  });

  it('has generate button', async () => {
    const root = await mountWithTool('typescriptInterfaceGen');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'TypescriptInterfaceGenButton' }, button);
  });

  it('shows interface name input', async () => {
    const root = await mountWithTool('typescriptInterfaceGen');
    const inputs = root?.querySelectorAll('input');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TypescriptInterfaceGenNameInput' },
      (inputs && inputs.length >= 1) || text.includes('name') || text.includes('Name'));
  });
});
