import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('ChmodCalculatorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('chmodCalculator');
      aiAssertTruthy({ name: 'ChmodMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'ChmodTitle' }, text, 'Chmod Calculator');
    });

    it('renders permission categories', async () => {
      const root = await mountWithTool('chmodCalculator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'ChmodOwner' }, text, 'Owner');
      aiAssertIncludes({ name: 'ChmodGroup' }, text, 'Group');
      aiAssertIncludes({ name: 'ChmodPublic' }, text, 'Public');
    });

    it('renders permission checkboxes', async () => {
      const root = await mountWithTool('chmodCalculator');
      const checkboxes = root?.querySelectorAll('input[type="checkbox"]');
      aiAssertTruthy({ name: 'ChmodCheckboxes' }, checkboxes && checkboxes.length >= 9);
    });
  });

  describe('Permission Calculation', () => {
    it('shows 755 for rwxr-xr-x', async () => {
      const root = await mountWithTool('chmodCalculator', {
        ownerRead: true,
        ownerWrite: true,
        ownerExecute: true,
        groupRead: true,
        groupWrite: false,
        groupExecute: true,
        publicRead: true,
        publicWrite: false,
        publicExecute: true
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Chmod755Octal' }, text, '755');
    });

    it('shows 644 for rw-r--r--', async () => {
      const root = await mountWithTool('chmodCalculator', {
        ownerRead: true,
        ownerWrite: true,
        ownerExecute: false,
        groupRead: true,
        groupWrite: false,
        groupExecute: false,
        publicRead: true,
        publicWrite: false,
        publicExecute: false
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Chmod644Octal' }, text, '644');
    });

    it('shows 777 for rwxrwxrwx', async () => {
      const root = await mountWithTool('chmodCalculator', {
        ownerRead: true,
        ownerWrite: true,
        ownerExecute: true,
        groupRead: true,
        groupWrite: true,
        groupExecute: true,
        publicRead: true,
        publicWrite: true,
        publicExecute: true
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Chmod777Octal' }, text, '777');
    });

    it('shows 000 for ---------', async () => {
      const root = await mountWithTool('chmodCalculator', {
        ownerRead: false,
        ownerWrite: false,
        ownerExecute: false,
        groupRead: false,
        groupWrite: false,
        groupExecute: false,
        publicRead: false,
        publicWrite: false,
        publicExecute: false
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Chmod000Octal' }, text, '000');
    });
  });

  describe('Checkbox Interaction', () => {
    it('toggles owner read permission', async () => {
      const root = await mountWithTool('chmodCalculator', {
        ownerRead: false
      });
      const checkboxes = root?.querySelectorAll('input[type="checkbox"]') as NodeListOf<HTMLInputElement>;
      // First checkbox should be owner read
      const ownerReadBox = Array.from(checkboxes).find(cb => {
        const label = cb.closest('label')?.textContent || '';
        return label.includes('Read') && cb.closest('div')?.textContent?.includes('Owner');
      }) || checkboxes[0];

      ownerReadBox?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();

      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { ownerRead?: boolean }>;
        return toolData.chmodCalculator?.ownerRead === true;
      });
      aiAssertTruthy({ name: 'ChmodToggleOwnerRead' }, stored);
    });
  });

  describe('Persistence', () => {
    it('persists permission state', async () => {
      const root = await mountWithTool('chmodCalculator', {
        ownerRead: true,
        ownerWrite: true,
        ownerExecute: false,
        groupRead: true
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { ownerRead?: boolean; groupRead?: boolean }>;
        return toolData.chmodCalculator?.ownerRead === true && toolData.chmodCalculator?.groupRead === true;
      });
      aiAssertTruthy({ name: 'ChmodPersist' }, stored);
    });
  });
});
