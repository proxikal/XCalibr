import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('KeycodeInfoTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('keycodeInfo');
      aiAssertTruthy({ name: 'KeycodeMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'KeycodeTitle' }, text, 'Keycode Info');
    });

    it('renders instructions', async () => {
      const root = await mountWithTool('keycodeInfo');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'KeycodeInstructions' }, text, 'Press');
    });

    it('renders key display labels', async () => {
      const root = await mountWithTool('keycodeInfo');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'KeycodeLabels' }, text, 'key');
    });
  });

  describe('History', () => {
    it('shows keycode in text', async () => {
      const root = await mountWithTool('keycodeInfo', {
        lastKey: 'Enter',
        lastCode: 'Enter',
        lastKeyCode: 13
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'KeycodeShow' }, text, 'Enter');
    });
  });

  describe('Persistence', () => {
    it('persists last key value', async () => {
      await mountWithTool('keycodeInfo', {
        lastKey: 'Space'
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { lastKey?: string }>;
        return toolData.keycodeInfo?.lastKey === 'Space';
      });
      aiAssertTruthy({ name: 'KeycodePersist' }, stored);
    });
  });
});
