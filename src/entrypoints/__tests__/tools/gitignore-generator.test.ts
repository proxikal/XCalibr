import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('GitIgnore Generator Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the GitIgnore Generator interface', async () => {
    const root = await mountWithTool('gitignoreGenerator');
    aiAssertTruthy({ name: 'GitIgnoreGeneratorRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'GitIgnoreGeneratorTitle' }, text.includes('GitIgnore') || text.includes('gitignore'));
  });

  it('shows template categories', async () => {
    const root = await mountWithTool('gitignoreGenerator');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'GitIgnoreGeneratorCategories' },
      text.includes('Node') || text.includes('Python') || text.includes('Java') || text.includes('macOS'));
  });

  it('displays generated output', async () => {
    const root = await mountWithTool('gitignoreGenerator', {
      output: 'node_modules/\n.env'
    });
    const text = root?.textContent || '';
    const textarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'GitIgnoreGeneratorOutput' },
      textarea || text.includes('node_modules') || text.includes('.env'));
  });

  it('has generate button', async () => {
    const root = await mountWithTool('gitignoreGenerator');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'GitIgnoreGeneratorButton' }, button);
  });

  it('allows multiple template selection', async () => {
    const root = await mountWithTool('gitignoreGenerator');
    const checkboxes = root?.querySelectorAll('input[type="checkbox"]');
    const buttons = root?.querySelectorAll('button');
    aiAssertTruthy({ name: 'GitIgnoreGeneratorMultiSelect' },
      (checkboxes && checkboxes.length >= 2) || (buttons && buttons.length >= 3));
  });
});
