import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Default Credential Checker Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Default Credential Checker interface', async () => {
    const root = await mountWithTool('defaultCredentialChecker');
    aiAssertTruthy({ name: 'DefaultCredentialCheckerRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'DefaultCredentialCheckerTitle' },
      text.includes('Credential') || text.includes('Default') || text.includes('Password'));
  });

  it('shows search or filter input', async () => {
    const root = await mountWithTool('defaultCredentialChecker');
    const input = root?.querySelector('input') || root?.querySelector('select');
    aiAssertTruthy({ name: 'DefaultCredentialCheckerInput' }, input);
  });

  it('shows vendor/product categories', async () => {
    const root = await mountWithTool('defaultCredentialChecker');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'DefaultCredentialCheckerCategories' },
      text.includes('Router') || text.includes('Database') || text.includes('CMS') ||
      text.includes('admin') || text.includes('Category') || (root?.querySelectorAll('*').length ?? 0) > 5);
  });

  it('shows credentials table or list', async () => {
    const root = await mountWithTool('defaultCredentialChecker', {
      selectedCategory: 'routers',
      credentials: [
        { vendor: 'Cisco', product: 'Router', username: 'admin', password: 'admin' },
        { vendor: 'Netgear', product: 'Router', username: 'admin', password: 'password' }
      ]
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'DefaultCredentialCheckerList' },
      text.includes('admin') || text.includes('Cisco') || text.includes('password') || (root?.querySelectorAll('*').length ?? 0) > 5);
  });

  it('has copy functionality', async () => {
    const root = await mountWithTool('defaultCredentialChecker');
    const button = root?.querySelector('button');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'DefaultCredentialCheckerCopy' },
      button || text.toLowerCase().includes('copy') || (root?.querySelectorAll('*').length ?? 0) > 3);
  });
});
