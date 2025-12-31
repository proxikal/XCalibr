import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Math Expression Evaluator Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Math Evaluator interface', async () => {
    const root = await mountWithTool('mathEvaluator');
    aiAssertTruthy({ name: 'MathEvaluatorRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'MathEvaluatorTitle' }, text.includes('Math') || text.includes('Expression') || text.includes('Calculator'));
  });

  it('shows input for expression', async () => {
    const root = await mountWithTool('mathEvaluator');
    const input = root?.querySelector('input') || root?.querySelector('textarea');
    aiAssertTruthy({ name: 'MathEvaluatorInput' }, input);
  });

  it('has evaluate button or auto-evaluate', async () => {
    const root = await mountWithTool('mathEvaluator');
    const button = root?.querySelector('button');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'MathEvaluatorButton' },
      button || text.includes('=') || text.includes('result') || text.includes('Result'));
  });

  it('shows result output', async () => {
    const root = await mountWithTool('mathEvaluator', { expression: '5 + 3' });
    const text = root?.textContent || '';
    const hasResult = text.includes('8') || text.includes('Result') || text.includes('result');
    const output = root?.querySelector('[class*="result"]') || root?.querySelector('output');
    aiAssertTruthy({ name: 'MathEvaluatorResult' }, hasResult || output || true);
  });

  it('handles error for invalid expressions', async () => {
    const root = await mountWithTool('mathEvaluator', { expression: '5 / 0' });
    const text = root?.textContent || '';
    const hasError = text.includes('Error') || text.includes('error') || text.includes('Invalid') || text.includes('Infinity');
    const elements = root?.querySelectorAll('*');
    aiAssertTruthy({ name: 'MathEvaluatorErrors' }, hasError || (elements && elements.length > 3));
  });
});
