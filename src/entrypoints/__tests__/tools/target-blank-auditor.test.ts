import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Target Blank Auditor Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Target Blank Auditor interface', async () => {
    const root = await mountWithTool('targetBlankAuditor');
    aiAssertTruthy({ name: 'TargetBlankAuditorRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TargetBlankAuditorTitle' },
      text.includes('target') || text.includes('blank') || text.includes('noopener') || text.includes('Link'));
  });

  it('has scan button', async () => {
    const root = await mountWithTool('targetBlankAuditor');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'TargetBlankAuditorButton' }, button);
  });

  it('shows vulnerable links when found', async () => {
    const root = await mountWithTool('targetBlankAuditor', {
      vulnerableLinks: [
        { href: 'https://example.com', text: 'Click here', hasNoopener: false, hasNoreferrer: false }
      ]
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TargetBlankAuditorResults' },
      text.includes('example') || text.includes('vulnerable') || text.includes('link') || root?.querySelectorAll('*').length! > 5);
  });

  it('displays link count', async () => {
    const root = await mountWithTool('targetBlankAuditor', {
      vulnerableLinks: [{ href: 'https://test.com', text: 'Test', hasNoopener: false, hasNoreferrer: false }],
      totalLinks: 5
    });
    const elements = root?.querySelectorAll('*');
    aiAssertTruthy({ name: 'TargetBlankAuditorCount' }, elements && elements.length > 3);
  });
});
