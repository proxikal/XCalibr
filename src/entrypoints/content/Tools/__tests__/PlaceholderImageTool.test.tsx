import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('PlaceholderImageTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('placeholderImage');
      aiAssertTruthy({ name: 'PlaceholderMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'PlaceholderTitle' }, text, 'Placeholder Image');
    });

    it('renders width input', async () => {
      const root = await mountWithTool('placeholderImage');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'PlaceholderWidth' }, text, 'Width');
    });

    it('renders height input', async () => {
      const root = await mountWithTool('placeholderImage');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'PlaceholderHeight' }, text, 'Height');
    });

    it('renders Generate button', async () => {
      const root = await mountWithTool('placeholderImage');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'PlaceholderGenerate' }, text, 'Generate');
    });
  });

  describe('URL Generation', () => {
    it('generates placeholder URL', async () => {
      const root = await mountWithTool('placeholderImage', {
        width: 300,
        height: 200
      });
      const text = root?.textContent || '';
      // Check that format options and buttons exist
      aiAssertIncludes({ name: 'PlaceholderFormat' }, text, 'PNG');
      aiAssertIncludes({ name: 'PlaceholderCopyUrl' }, text, 'Copy URL');
    });
  });

  describe('Persistence', () => {
    it('persists width value', async () => {
      await mountWithTool('placeholderImage', {
        width: 400
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { width?: number }>;
        return toolData.placeholderImage?.width === 400;
      });
      aiAssertTruthy({ name: 'PlaceholderPersist' }, stored);
    });
  });
});
