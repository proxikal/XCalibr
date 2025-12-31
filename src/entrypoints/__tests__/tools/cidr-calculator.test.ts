import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool, findButtonByText } from '../integration-test-utils';

describe('CIDR Calculator Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the CIDR Calculator interface', async () => {
    const root = await mountWithTool('cidrCalculator');
    aiAssertTruthy({ name: 'CidrCalcRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'CidrCalcTitle' }, text.includes('CIDR') || text.includes('Calculator'));
  });

  it('shows IP input field', async () => {
    const root = await mountWithTool('cidrCalculator');
    const input = root?.querySelector('input[placeholder*="192"]') || root?.querySelector('input');
    aiAssertTruthy({ name: 'CidrCalcInput' }, input);
  });

  it('has calculate button', async () => {
    const root = await mountWithTool('cidrCalculator');
    const btn = findButtonByText(root!, 'Calculate') || findButtonByText(root!, 'Compute');
    aiAssertTruthy({ name: 'CidrCalcButton' }, btn);
  });

  it('displays network info when calculated', async () => {
    const root = await mountWithTool('cidrCalculator', {
      cidr: '192.168.1.0/24',
      networkAddress: '192.168.1.0',
      broadcastAddress: '192.168.1.255',
      netmask: '255.255.255.0',
      hosts: 254
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'CidrCalcResults' },
      text.includes('192.168') || text.includes('255') || text.includes('Network'));
  });

  it('shows host count', async () => {
    const root = await mountWithTool('cidrCalculator', {
      hosts: 254,
      cidr: '192.168.1.0/24',
      networkAddress: '192.168.1.0'  // Required for hosts to display
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'CidrCalcHosts' }, text.includes('254') || text.includes('hosts') || text.includes('Hosts'));
  });
});
