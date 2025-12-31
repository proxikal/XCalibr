import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('MacVendorLookupTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('macVendorLookup');
      aiAssertTruthy({ name: 'MacMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'MacTitle' }, text, 'MAC Address Vendor Lookup');
    });

    it('renders Lookup Vendor button', async () => {
      const root = await mountWithTool('macVendorLookup');
      const lookupBtn = findButtonByText(root!, 'Lookup Vendor');
      aiAssertTruthy({ name: 'MacLookupBtn' }, lookupBtn);
    });

    it('renders MAC input field', async () => {
      const root = await mountWithTool('macVendorLookup');
      const inputs = root?.querySelectorAll('input[type="text"]');
      aiAssertTruthy({ name: 'MacInput' }, inputs && inputs.length > 0);
    });
  });

  describe('Vendor Lookup', () => {
    it('finds Apple vendor', async () => {
      const root = await mountWithTool('macVendorLookup', {
        mac: 'AC:DE:48:00:00:00'
      });
      const lookupBtn = findButtonByText(root!, 'Lookup Vendor');
      lookupBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { vendor?: string }>;
        return !!toolData.macVendorLookup?.vendor;
      });
      const vendor = (stored?.toolData as Record<string, { vendor?: string }> | undefined)
        ?.macVendorLookup?.vendor;
      aiAssertIncludes({ name: 'MacApple' }, vendor || '', 'Apple');
    });

    it('finds Cisco vendor', async () => {
      const root = await mountWithTool('macVendorLookup', {
        mac: '00:00:0C:00:00:00'
      });
      const lookupBtn = findButtonByText(root!, 'Lookup Vendor');
      lookupBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { vendor?: string }>;
        return !!toolData.macVendorLookup?.vendor;
      });
      const vendor = (stored?.toolData as Record<string, { vendor?: string }> | undefined)
        ?.macVendorLookup?.vendor;
      aiAssertIncludes({ name: 'MacCisco' }, vendor || '', 'Cisco');
    });

    it('finds VMware vendor', async () => {
      const root = await mountWithTool('macVendorLookup', {
        mac: '00:50:56:00:00:00'
      });
      const lookupBtn = findButtonByText(root!, 'Lookup Vendor');
      lookupBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { vendor?: string }>;
        return !!toolData.macVendorLookup?.vendor;
      });
      const vendor = (stored?.toolData as Record<string, { vendor?: string }> | undefined)
        ?.macVendorLookup?.vendor;
      aiAssertIncludes({ name: 'MacVMware' }, vendor || '', 'VMware');
    });

    it('handles MAC without colons', async () => {
      const root = await mountWithTool('macVendorLookup', {
        mac: 'ACDE48000000'
      });
      const lookupBtn = findButtonByText(root!, 'Lookup Vendor');
      lookupBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { vendor?: string }>;
        return !!toolData.macVendorLookup?.vendor;
      });
      const vendor = (stored?.toolData as Record<string, { vendor?: string }> | undefined)
        ?.macVendorLookup?.vendor;
      aiAssertIncludes({ name: 'MacNoColons' }, vendor || '', 'Apple');
    });
  });

  describe('Error Handling', () => {
    it('shows error for short MAC', async () => {
      const root = await mountWithTool('macVendorLookup', {
        mac: 'AA:BB'
      });
      const lookupBtn = findButtonByText(root!, 'Lookup Vendor');
      lookupBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { error?: string }>;
        return !!toolData.macVendorLookup?.error;
      });
      const hasError = !!(stored?.toolData as Record<string, { error?: string }> | undefined)
        ?.macVendorLookup?.error;
      aiAssertTruthy({ name: 'MacShortError' }, hasError);
    });

    it('shows error for unknown vendor', async () => {
      const root = await mountWithTool('macVendorLookup', {
        mac: 'FF:FF:FF:00:00:00'
      });
      const lookupBtn = findButtonByText(root!, 'Lookup Vendor');
      lookupBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { error?: string }>;
        return !!toolData.macVendorLookup?.error;
      });
      const hasError = !!(stored?.toolData as Record<string, { error?: string }> | undefined)
        ?.macVendorLookup?.error;
      aiAssertTruthy({ name: 'MacUnknownError' }, hasError);
    });
  });

  describe('Results Display', () => {
    it('displays vendor name after lookup', async () => {
      const root = await mountWithTool('macVendorLookup', {
        vendor: 'Apple'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'MacDisplayVendor' }, text, 'Apple');
    });
  });
});
