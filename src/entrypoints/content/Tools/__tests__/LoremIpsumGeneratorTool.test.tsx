import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('LoremIpsumGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('loremIpsumGenerator');
      aiAssertTruthy({ name: 'LoremMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'LoremTitle' }, text, 'Lorem Ipsum Generator');
    });

    it('renders count input', async () => {
      const root = await mountWithTool('loremIpsumGenerator');
      const inputs = root?.querySelectorAll('input[type="number"]') || [];
      aiAssertTruthy({ name: 'LoremCountInput' }, inputs.length >= 1);
    });

    it('renders type selector', async () => {
      const root = await mountWithTool('loremIpsumGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'LoremParagraphs' }, text, 'Paragraphs');
    });

    it('renders Generate button', async () => {
      const root = await mountWithTool('loremIpsumGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'LoremGenerate' }, text, 'Generate');
    });
  });

  describe('Generation', () => {
    it('generates Lorem Ipsum text', async () => {
      const root = await mountWithTool('loremIpsumGenerator', {
        count: 1,
        type: 'paragraphs',
        output: 'Lorem ipsum dolor sit amet'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'LoremOutput' }, text, 'Lorem ipsum');
    });
  });

  describe('Persistence', () => {
    it('persists count value', async () => {
      await mountWithTool('loremIpsumGenerator', {
        count: 5
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { count?: number }>;
        return toolData.loremIpsumGenerator?.count === 5;
      });
      aiAssertTruthy({ name: 'LoremPersist' }, stored);
    });
  });
});
