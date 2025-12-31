import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('CaseConverterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('caseConverter');
      aiAssertTruthy({ name: 'CaseMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CaseTitle' }, text, 'Case');
    });

    it('renders camelCase option', async () => {
      const root = await mountWithTool('caseConverter');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CaseCamel' }, text, 'camel');
    });

    it('renders snake_case option', async () => {
      const root = await mountWithTool('caseConverter');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CaseSnake' }, text, 'snake');
    });
  });

  describe('Conversion', () => {
    it('shows converted output', async () => {
      const root = await mountWithTool('caseConverter', {
        input: 'hello world',
        outputs: { camelCase: 'helloWorld' }
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CaseOutput' }, text, 'helloWorld');
    });
  });

  describe('Persistence', () => {
    it('persists input value', async () => {
      await mountWithTool('caseConverter', {
        input: 'test string'
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { input?: string }>;
        return toolData.caseConverter?.input === 'test string';
      });
      aiAssertTruthy({ name: 'CasePersist' }, stored);
    });
  });
});
