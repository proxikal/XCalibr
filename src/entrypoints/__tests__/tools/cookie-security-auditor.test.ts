import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Cookie Security Auditor Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Cookie Security Auditor interface', async () => {
    const root = await mountWithTool('cookieSecurityAuditor');
    aiAssertTruthy({ name: 'CookieSecurityAuditorRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'CookieSecurityAuditorTitle' },
      text.includes('Cookie') || text.includes('Security') || text.includes('Audit'));
  });

  it('has scan button', async () => {
    const root = await mountWithTool('cookieSecurityAuditor');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'CookieSecurityAuditorButton' }, button);
  });

  it('shows cookie list or analysis area', async () => {
    const root = await mountWithTool('cookieSecurityAuditor');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'CookieSecurityAuditorAnalysis' },
      text.includes('HttpOnly') || text.includes('Secure') || text.includes('SameSite') || text.includes('cookie'));
  });

  it('displays security flags indicators', async () => {
    const root = await mountWithTool('cookieSecurityAuditor', {
      cookies: [{
        name: 'session',
        value: 'abc123',
        httpOnly: true,
        secure: true,
        sameSite: 'Strict'
      }]
    });
    const text = root?.textContent || '';
    const hasFlags = text.includes('HttpOnly') || text.includes('Secure') || text.includes('SameSite');
    aiAssertTruthy({ name: 'CookieSecurityAuditorFlags' }, hasFlags);
  });
});
