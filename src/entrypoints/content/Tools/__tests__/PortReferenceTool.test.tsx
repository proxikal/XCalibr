import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitForState,
  typeInput
} from '../../../__tests__/integration-test-utils';

describe('PortReferenceTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('portReference');
      aiAssertTruthy({ name: 'PortMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'PortTitle' }, text, 'Port Number Reference');
    });

    it('renders table headers', async () => {
      const root = await mountWithTool('portReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'PortHeader' }, text, 'Port');
      aiAssertIncludes({ name: 'ProtoHeader' }, text, 'Proto');
      aiAssertIncludes({ name: 'ServiceHeader' }, text, 'Service');
    });

    it('renders search input', async () => {
      const root = await mountWithTool('portReference');
      const inputs = root?.querySelectorAll('input[type="text"]');
      aiAssertTruthy({ name: 'PortSearchInput' }, inputs && inputs.length > 0);
    });
  });

  describe('Port Data', () => {
    it('shows HTTP port 80', async () => {
      const root = await mountWithTool('portReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Port80' }, text, '80');
      aiAssertIncludes({ name: 'PortHTTP' }, text, 'HTTP');
    });

    it('shows HTTPS port 443', async () => {
      const root = await mountWithTool('portReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Port443' }, text, '443');
      aiAssertIncludes({ name: 'PortHTTPS' }, text, 'HTTPS');
    });

    it('shows SSH port 22', async () => {
      const root = await mountWithTool('portReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Port22' }, text, '22');
      aiAssertIncludes({ name: 'PortSSH' }, text, 'SSH');
    });

    it('shows MySQL port 3306', async () => {
      const root = await mountWithTool('portReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Port3306' }, text, '3306');
      aiAssertIncludes({ name: 'PortMySQL' }, text, 'MySQL');
    });

    it('shows DNS port 53', async () => {
      const root = await mountWithTool('portReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Port53' }, text, '53');
      aiAssertIncludes({ name: 'PortDNS' }, text, 'DNS');
    });
  });

  describe('Search Functionality', () => {
    it('filters by port number', async () => {
      const root = await mountWithTool('portReference', {
        search: '443'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'PortSearch443' }, text, 'HTTPS');
    });

    it('filters by service name', async () => {
      const root = await mountWithTool('portReference', {
        search: 'mysql'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'PortSearchMySQL' }, text, '3306');
    });

    it('persists search value in state', async () => {
      const root = await mountWithTool('portReference', {
        search: 'ssh'
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { search?: string }>;
        return toolData.portReference?.search === 'ssh';
      });
      aiAssertTruthy({ name: 'PortSearchPersist' }, stored);
    });
  });

  describe('Protocol Information', () => {
    it('shows TCP protocol', async () => {
      const root = await mountWithTool('portReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'PortTCP' }, text, 'TCP');
    });

    it('shows UDP protocol', async () => {
      const root = await mountWithTool('portReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'PortUDP' }, text, 'UDP');
    });
  });
});
