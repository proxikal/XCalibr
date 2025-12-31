import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('JWT Attack Advisor Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the JWT Attack Advisor interface', async () => {
    const root = await mountWithTool('jwtAttackAdvisor');
    aiAssertTruthy({ name: 'JwtAttackAdvisorRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'JwtAttackAdvisorTitle' },
      text.includes('JWT') || text.includes('Attack') || text.includes('Token') || text.includes('Advisor'));
  });

  it('has JWT input area', async () => {
    const root = await mountWithTool('jwtAttackAdvisor');
    const input = root?.querySelector('input') || root?.querySelector('textarea');
    aiAssertTruthy({ name: 'JwtAttackAdvisorInput' }, input);
  });

  it('has analyze button', async () => {
    const root = await mountWithTool('jwtAttackAdvisor');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'JwtAttackAdvisorButton' }, button);
  });

  it('shows attack vectors or recommendations', async () => {
    const root = await mountWithTool('jwtAttackAdvisor', {
      token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
      attacks: [{ name: 'Algorithm Confusion', description: 'Try alg:none attack' }]
    });
    const text = root?.textContent || '';
    const hasAttacks = text.includes('attack') || text.includes('algorithm') || text.includes('none') || text.includes('vector');
    aiAssertTruthy({ name: 'JwtAttackAdvisorVectors' }, hasAttacks);
  });
});
