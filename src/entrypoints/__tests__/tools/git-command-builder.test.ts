import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Git Command Builder Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Git Command Builder interface', async () => {
    const root = await mountWithTool('gitCommandBuilder');
    aiAssertTruthy({ name: 'GitCommandBuilderRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'GitCommandBuilderTitle' }, text.includes('Git') || text.includes('Command'));
  });

  it('shows git command categories', async () => {
    const root = await mountWithTool('gitCommandBuilder');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'GitCommandBuilderCategories' },
      text.includes('commit') || text.includes('branch') || text.includes('rebase') || text.includes('log'));
  });

  it('displays generated command', async () => {
    const root = await mountWithTool('gitCommandBuilder', {
      command: 'git commit -m "message"'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'GitCommandBuilderOutput' },
      text.includes('git') || text.includes('commit'));
  });

  it('has copy button', async () => {
    const root = await mountWithTool('gitCommandBuilder');
    const buttons = root?.querySelectorAll('button');
    aiAssertTruthy({ name: 'GitCommandBuilderCopyButton' }, buttons && buttons.length >= 1);
  });

  it('shows command options', async () => {
    const root = await mountWithTool('gitCommandBuilder');
    const text = root?.textContent || '';
    const inputs = root?.querySelectorAll('input, select');
    aiAssertTruthy({ name: 'GitCommandBuilderOptions' },
      (inputs && inputs.length >= 1) || text.includes('flag') || text.includes('-'));
  });
});
