import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('OpenGraphPreviewerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('openGraphPreviewer');
      aiAssertTruthy({ name: 'OgMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'OgTitle' }, text, 'Open Graph Preview');
    });

    it('renders title input', async () => {
      const root = await mountWithTool('openGraphPreviewer');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'OgTitleInput' }, text, 'Title');
    });

    it('renders description input', async () => {
      const root = await mountWithTool('openGraphPreviewer');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'OgDescInput' }, text, 'Description');
    });

    it('renders platform tabs', async () => {
      const root = await mountWithTool('openGraphPreviewer');
      const text = root?.textContent || '';
      aiAssertTruthy({ name: 'OgPlatforms' }, text.includes('Facebook') || text.includes('Twitter') || text.includes('LinkedIn'));
    });
  });

  describe('Preview Display', () => {
    it('shows preview with title', async () => {
      const root = await mountWithTool('openGraphPreviewer', {
        title: 'My Page Title',
        description: 'Page description',
        imageUrl: 'https://example.com/image.jpg'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'OgPreviewTitle' }, text, 'My Page Title');
    });

    it('shows preview with description', async () => {
      const root = await mountWithTool('openGraphPreviewer', {
        title: 'Test',
        description: 'This is the page description'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'OgPreviewDesc' }, text, 'This is the page description');
    });
  });

  describe('Persistence', () => {
    it('persists title', async () => {
      const root = await mountWithTool('openGraphPreviewer', {
        title: 'Persisted Title'
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { title?: string }>;
        return toolData.openGraphPreviewer?.title === 'Persisted Title';
      });
      aiAssertTruthy({ name: 'OgPersist' }, stored);
    });
  });
});
