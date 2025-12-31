import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('MetaTagGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('metaTagGenerator');
      aiAssertTruthy({ name: 'MetaMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'MetaTitle' }, text, 'Meta Tag Generator');
    });

    it('renders title input', async () => {
      const root = await mountWithTool('metaTagGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'MetaTitleInput' }, text, 'Title');
    });

    it('renders description input', async () => {
      const root = await mountWithTool('metaTagGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'MetaDescInput' }, text, 'Description');
    });

    it('renders Copy button', async () => {
      const root = await mountWithTool('metaTagGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'MetaCopyBtn' }, text, 'Copy');
    });
  });

  describe('Tag Generation', () => {
    it('generates title meta tag', async () => {
      const root = await mountWithTool('metaTagGenerator', {
        title: 'My Page Title'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'MetaGenerateTitle' }, text, '<title>');
      aiAssertIncludes({ name: 'MetaTitleValue' }, text, 'My Page Title');
    });

    it('generates description meta tag', async () => {
      const root = await mountWithTool('metaTagGenerator', {
        description: 'This is a page description'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'MetaDescTag' }, text, 'description');
    });

    it('generates viewport meta tag', async () => {
      const root = await mountWithTool('metaTagGenerator', {
        viewport: true
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'MetaViewport' }, text, 'viewport');
    });

    it('generates robots meta tag', async () => {
      const root = await mountWithTool('metaTagGenerator', {
        robots: 'index, follow'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'MetaRobots' }, text, 'robots');
    });
  });

  describe('Persistence', () => {
    it('persists title', async () => {
      const root = await mountWithTool('metaTagGenerator', {
        title: 'Test Title'
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { title?: string }>;
        return toolData.metaTagGenerator?.title === 'Test Title';
      });
      aiAssertTruthy({ name: 'MetaPersist' }, stored);
    });
  });
});
