import { beforeEach, describe, it } from 'vitest';
import { aiAssertEqual, aiAssertIncludes, aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitFor,
  findButtonByText,
  waitForState,
  getState,
  setState,
  mountContent,
  findPreviewFrame
} from '../../../__tests__/integration-test-utils';

describe('LiveLinkPreviewTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('toggles Live Link Preview activation state', async () => {
      const root = await mountWithTool('liveLinkPreview', { isActive: false });
      if (!root) return;
      const button = await waitFor(() => findButtonByText(root, 'Inactive'));
      aiAssertTruthy({ name: 'LiveLinkPreviewToggleButton' }, button);
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { isActive?: boolean }>;
        return toolData.liveLinkPreview?.isActive === true;
      });
      const isActive = (stored?.toolData as Record<string, { isActive?: boolean }> | undefined)
        ?.liveLinkPreview?.isActive ?? false;
      aiAssertEqual({ name: 'LiveLinkPreviewToggleState' }, isActive, true);
    });

    it('shows link preview iframe on hover when active', async () => {
      document.body.innerHTML = '<a href="https://example.com">Example</a>';
      await mountWithTool('liveLinkPreview', { isActive: true });
      const anchor = document.querySelector('a') as HTMLAnchorElement | null;
      if (!anchor) return;
      anchor.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
      await new Promise((resolve) => setTimeout(resolve, 600));
      const frame = findPreviewFrame();
      aiAssertTruthy({ name: 'LiveLinkPreviewFrame' }, frame);
      aiAssertIncludes(
        { name: 'LiveLinkPreviewFrameSrc' },
        frame?.getAttribute('src') ?? '',
        'https://example.com'
      );
    });

    it('does not show link preview when inactive', async () => {
      document.body.innerHTML = '<a href="https://example.com">Example</a>';
      await mountWithTool('liveLinkPreview', { isActive: false });
      const anchor = document.querySelector('a') as HTMLAnchorElement | null;
      if (!anchor) return;
      anchor.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
      await new Promise((resolve) => setTimeout(resolve, 600));
      const frame = findPreviewFrame();
      aiAssertTruthy({ name: 'LiveLinkPreviewNoFrame' }, !frame);
    });

    it('reacts to persisted activation state changes', async () => {
      document.body.innerHTML = '<a href="https://example.com">Example</a>';
      await setState({ isOpen: true, isVisible: true });
      await mountContent();
      const nextState = await getState();
      const STORAGE_KEY = 'xcalibr_state';
      await chrome.storage.local.set({
        [STORAGE_KEY]: {
          ...nextState,
          toolData: {
            ...nextState.toolData,
            liveLinkPreview: { isActive: true }
          }
        }
      });
      await flushPromises();
      const anchor = document.querySelector('a') as HTMLAnchorElement | null;
      if (!anchor) return;
      anchor.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
      await new Promise((resolve) => setTimeout(resolve, 600));
      const frame = findPreviewFrame();
      aiAssertTruthy({ name: 'LiveLinkPreviewPersistFrame' }, frame);
    });
  });
});
