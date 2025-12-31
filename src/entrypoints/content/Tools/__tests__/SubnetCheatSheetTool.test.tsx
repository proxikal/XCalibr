import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('SubnetCheatSheetTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('subnetCheatSheet');
      aiAssertTruthy({ name: 'SubnetMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'SubnetTitle' }, text, 'Subnet Mask Cheat Sheet');
    });

    it('renders table headers', async () => {
      const root = await mountWithTool('subnetCheatSheet');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'SubnetCIDRHeader' }, text, 'CIDR');
      aiAssertIncludes({ name: 'SubnetDecimalHeader' }, text, 'Decimal');
      aiAssertIncludes({ name: 'SubnetHexHeader' }, text, 'Hex');
      aiAssertIncludes({ name: 'SubnetHostsHeader' }, text, 'Hosts');
    });

    it('renders /24 subnet row', async () => {
      const root = await mountWithTool('subnetCheatSheet');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Subnet24CIDR' }, text, '/24');
      aiAssertIncludes({ name: 'Subnet24Mask' }, text, '255.255.255.0');
    });

    it('renders /32 subnet row', async () => {
      const root = await mountWithTool('subnetCheatSheet');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Subnet32CIDR' }, text, '/32');
      aiAssertIncludes({ name: 'Subnet32Mask' }, text, '255.255.255.255');
    });

    it('renders /8 subnet row', async () => {
      const root = await mountWithTool('subnetCheatSheet');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Subnet8CIDR' }, text, '/8');
      aiAssertIncludes({ name: 'Subnet8Mask' }, text, '255.0.0.0');
    });
  });

  describe('Table Data', () => {
    it('shows host count for /24', async () => {
      const root = await mountWithTool('subnetCheatSheet');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'SubnetHosts24' }, text, '254');
    });

    it('shows hex value for /24', async () => {
      const root = await mountWithTool('subnetCheatSheet');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'SubnetHex24' }, text, 'FFFFFF00');
    });

    it('shows hex value for /16', async () => {
      const root = await mountWithTool('subnetCheatSheet');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'SubnetHex16' }, text, 'FFFF0000');
    });
  });

  describe('Row Selection', () => {
    it('allows clicking a row to select', async () => {
      const root = await mountWithTool('subnetCheatSheet');
      const rows = root?.querySelectorAll('tr');
      aiAssertTruthy({ name: 'SubnetRowsExist' }, rows && rows.length > 1);

      // Click on the /24 row
      const dataRows = Array.from(rows || []).slice(1); // Skip header
      const row24 = dataRows.find(r => r.textContent?.includes('/24'));
      row24?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();

      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { selectedPrefix?: number }>;
        return toolData.subnetCheatSheet?.selectedPrefix === 24;
      });
      aiAssertTruthy({ name: 'SubnetRowClick24' }, stored);
    });
  });

  describe('Multiple Subnets', () => {
    it('displays all common subnet prefixes', async () => {
      const root = await mountWithTool('subnetCheatSheet');
      const text = root?.textContent || '';
      const prefixes = ['/32', '/31', '/30', '/29', '/28', '/27', '/26', '/25', '/24'];
      prefixes.forEach(prefix => {
        aiAssertIncludes({ name: `Subnet${prefix}` }, text, prefix);
      });
    });
  });

  describe('Persistence', () => {
    it('persists selected prefix', async () => {
      const root = await mountWithTool('subnetCheatSheet', {
        selectedPrefix: 24
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { selectedPrefix?: number }>;
        return toolData.subnetCheatSheet?.selectedPrefix === 24;
      });
      aiAssertTruthy({ name: 'SubnetPersist' }, stored);
    });
  });
});
