import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('PermissionsReferenceTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('permissionsReference');
      aiAssertTruthy({ name: 'PermsMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'PermsTitle' }, text, 'Permissions');
    });

    it('renders search input', async () => {
      const root = await mountWithTool('permissionsReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'PermsSearch' }, text, 'Search');
    });

    it('renders permission list', async () => {
      const root = await mountWithTool('permissionsReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'PermsList' }, text, 'storage');
    });
  });

  describe('Search', () => {
    it('filters permissions by search', async () => {
      const root = await mountWithTool('permissionsReference', {
        search: 'tabs'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'PermsFilter' }, text, 'tabs');
    });
  });

  describe('Persistence', () => {
    it('persists search value', async () => {
      await mountWithTool('permissionsReference', {
        search: 'storage'
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { search?: string }>;
        return toolData.permissionsReference?.search === 'storage';
      });
      aiAssertTruthy({ name: 'PermsPersist' }, stored);
    });
  });
});
