import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('ManifestValidatorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('manifestValidator');
      aiAssertTruthy({ name: 'ManifestMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'ManifestTitle' }, text, 'Manifest');
    });

    it('renders input area', async () => {
      const root = await mountWithTool('manifestValidator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'ManifestInput' }, text, 'manifest');
    });

    it('renders validate button', async () => {
      const root = await mountWithTool('manifestValidator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'ManifestValidate' }, text, 'Validate');
    });
  });

  describe('Validation', () => {
    it('shows errors for invalid manifest', async () => {
      const root = await mountWithTool('manifestValidator', {
        input: '{ "name": "Test" }',
        errors: ['Missing required field: version']
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'ManifestErrors' }, text, 'Missing');
    });
  });

  describe('Persistence', () => {
    it('persists input value', async () => {
      await mountWithTool('manifestValidator', {
        input: '{ "test": true }'
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { input?: string }>;
        return toolData.manifestValidator?.input === '{ "test": true }';
      });
      aiAssertTruthy({ name: 'ManifestPersist' }, stored);
    });
  });
});
