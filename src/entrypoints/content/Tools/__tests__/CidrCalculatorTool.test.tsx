import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertEqual, aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('CidrCalculatorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('cidrCalculator');
      aiAssertTruthy({ name: 'CidrMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CidrTitle' }, text, 'CIDR Calculator');
    });

    it('renders Calculate button', async () => {
      const root = await mountWithTool('cidrCalculator');
      const calculateBtn = findButtonByText(root!, 'Calculate');
      aiAssertTruthy({ name: 'CidrCalculateBtn' }, calculateBtn);
    });

    it('renders CIDR input field', async () => {
      const root = await mountWithTool('cidrCalculator');
      const input = root?.querySelector('input[type="text"]');
      aiAssertTruthy({ name: 'CidrInput' }, input);
    });

    it('shows placeholder text', async () => {
      const root = await mountWithTool('cidrCalculator');
      const inputs = Array.from(root?.querySelectorAll('input[type="text"]') || []) as HTMLInputElement[];
      const cidrInput = inputs.find(i => i.placeholder === '192.168.1.0/24');
      aiAssertTruthy({ name: 'CidrPlaceholder' }, cidrInput);
    });
  });

  describe('CIDR Calculation', () => {
    it('calculates /24 network correctly', async () => {
      const root = await mountWithTool('cidrCalculator', {
        cidr: '192.168.1.0/24'
      });
      const calculateBtn = findButtonByText(root!, 'Calculate');
      calculateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { networkAddress?: string }>;
        return !!toolData.cidrCalculator?.networkAddress;
      });
      const data = (stored?.toolData as Record<string, { networkAddress?: string; hosts?: number }> | undefined)
        ?.cidrCalculator;
      aiAssertEqual({ name: 'CidrNetwork24' }, data?.networkAddress, '192.168.1.0');
      aiAssertEqual({ name: 'CidrHosts24' }, data?.hosts, 254);
    });

    it('calculates /8 network correctly', async () => {
      const root = await mountWithTool('cidrCalculator', {
        cidr: '10.0.0.0/8'
      });
      const calculateBtn = findButtonByText(root!, 'Calculate');
      calculateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { networkAddress?: string }>;
        return !!toolData.cidrCalculator?.networkAddress;
      });
      const data = (stored?.toolData as Record<string, { networkAddress?: string; netmask?: string }> | undefined)
        ?.cidrCalculator;
      aiAssertEqual({ name: 'CidrNetwork8' }, data?.networkAddress, '10.0.0.0');
      aiAssertEqual({ name: 'CidrNetmask8' }, data?.netmask, '255.0.0.0');
    });

    it('calculates /16 network correctly', async () => {
      const root = await mountWithTool('cidrCalculator', {
        cidr: '172.16.0.0/16'
      });
      const calculateBtn = findButtonByText(root!, 'Calculate');
      calculateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { networkAddress?: string }>;
        return !!toolData.cidrCalculator?.networkAddress;
      });
      const data = (stored?.toolData as Record<string, { networkAddress?: string; broadcastAddress?: string }> | undefined)
        ?.cidrCalculator;
      aiAssertEqual({ name: 'CidrNetwork16' }, data?.networkAddress, '172.16.0.0');
      aiAssertEqual({ name: 'CidrBroadcast16' }, data?.broadcastAddress, '172.16.255.255');
    });

    it('calculates /30 network correctly (point-to-point)', async () => {
      const root = await mountWithTool('cidrCalculator', {
        cidr: '192.168.1.0/30'
      });
      const calculateBtn = findButtonByText(root!, 'Calculate');
      calculateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { hosts?: number }>;
        return toolData.cidrCalculator?.hosts !== undefined;
      });
      const data = (stored?.toolData as Record<string, { hosts?: number }> | undefined)
        ?.cidrCalculator;
      aiAssertEqual({ name: 'CidrHosts30' }, data?.hosts, 2);
    });

    it('calculates wildcard mask correctly', async () => {
      const root = await mountWithTool('cidrCalculator', {
        cidr: '192.168.1.0/24'
      });
      const calculateBtn = findButtonByText(root!, 'Calculate');
      calculateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { wildcardMask?: string }>;
        return !!toolData.cidrCalculator?.wildcardMask;
      });
      const data = (stored?.toolData as Record<string, { wildcardMask?: string }> | undefined)
        ?.cidrCalculator;
      aiAssertEqual({ name: 'CidrWildcard24' }, data?.wildcardMask, '0.0.0.255');
    });
  });

  describe('Error Handling', () => {
    it('shows error for invalid CIDR format', async () => {
      const root = await mountWithTool('cidrCalculator', {
        cidr: 'invalid'
      });
      const calculateBtn = findButtonByText(root!, 'Calculate');
      calculateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { error?: string }>;
        return !!toolData.cidrCalculator?.error;
      });
      const hasError = !!(stored?.toolData as Record<string, { error?: string }> | undefined)
        ?.cidrCalculator?.error;
      aiAssertTruthy({ name: 'CidrInvalidFormatError' }, hasError);
    });

    it('shows error for prefix > 32', async () => {
      const root = await mountWithTool('cidrCalculator', {
        cidr: '192.168.1.0/33'
      });
      const calculateBtn = findButtonByText(root!, 'Calculate');
      calculateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { error?: string }>;
        return !!toolData.cidrCalculator?.error;
      });
      const hasError = !!(stored?.toolData as Record<string, { error?: string }> | undefined)
        ?.cidrCalculator?.error;
      aiAssertTruthy({ name: 'CidrPrefixTooLargeError' }, hasError);
    });

    it('shows error for invalid IP octet', async () => {
      const root = await mountWithTool('cidrCalculator', {
        cidr: '192.168.256.0/24'
      });
      const calculateBtn = findButtonByText(root!, 'Calculate');
      calculateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { error?: string }>;
        return !!toolData.cidrCalculator?.error;
      });
      const hasError = !!(stored?.toolData as Record<string, { error?: string }> | undefined)
        ?.cidrCalculator?.error;
      aiAssertTruthy({ name: 'CidrInvalidOctetError' }, hasError);
    });
  });

  describe('Results Display', () => {
    it('displays network address after calculation', async () => {
      const root = await mountWithTool('cidrCalculator', {
        networkAddress: '192.168.1.0',
        broadcastAddress: '192.168.1.255',
        netmask: '255.255.255.0',
        wildcardMask: '0.0.0.255',
        firstHost: '192.168.1.1',
        lastHost: '192.168.1.254',
        hosts: 254
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CidrDisplayNetwork' }, text, '192.168.1.0');
    });

    it('displays usable hosts count', async () => {
      const root = await mountWithTool('cidrCalculator', {
        networkAddress: '192.168.1.0',
        hosts: 254
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CidrDisplayHosts' }, text, '254');
    });
  });
});
