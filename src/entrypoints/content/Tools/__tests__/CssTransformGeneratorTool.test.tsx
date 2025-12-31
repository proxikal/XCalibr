import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('CssTransformGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('cssTransformGenerator');
      aiAssertTruthy({ name: 'TransformMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'TransformTitle' }, text, 'CSS Transform Generator');
    });

    it('renders translate control', async () => {
      const root = await mountWithTool('cssTransformGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'TransformTranslate' }, text, 'Translate');
    });

    it('renders rotate control', async () => {
      const root = await mountWithTool('cssTransformGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'TransformRotate' }, text, 'Rotate');
    });

    it('renders scale control', async () => {
      const root = await mountWithTool('cssTransformGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'TransformScale' }, text, 'Scale');
    });

    it('renders Copy button', async () => {
      const root = await mountWithTool('cssTransformGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'TransformCopy' }, text, 'Copy');
    });
  });

  describe('CSS Output', () => {
    it('generates transform CSS', async () => {
      const root = await mountWithTool('cssTransformGenerator', {
        translateX: 10,
        translateY: 20,
        rotate: 45,
        scaleX: 1.5
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'TransformCSS' }, text, 'transform:');
    });
  });

  describe('Persistence', () => {
    it('persists rotate value', async () => {
      await mountWithTool('cssTransformGenerator', {
        rotate: 90
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { rotate?: number }>;
        return toolData.cssTransformGenerator?.rotate === 90;
      });
      aiAssertTruthy({ name: 'TransformPersist' }, stored);
    });
  });
});
