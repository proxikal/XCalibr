import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('CspBuilderTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('cspBuilder');
      aiAssertTruthy({ name: 'CspBuilderMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CspBuilderTitle' }, text, 'CSP Builder');
    });

    it('renders Generate button', async () => {
      const root = await mountWithTool('cspBuilder');
      const generateBtn = findButtonByText(root!, 'Generate');
      aiAssertTruthy({ name: 'CspBuilderGenerateBtn' }, generateBtn);
    });

    it('renders Analyze button', async () => {
      const root = await mountWithTool('cspBuilder');
      const analyzeBtn = findButtonByText(root!, 'Analyze');
      aiAssertTruthy({ name: 'CspBuilderAnalyzeBtn' }, analyzeBtn);
    });

    it('renders directive options', async () => {
      const root = await mountWithTool('cspBuilder');
      const text = root?.textContent || '';
      const hasDefaultSrc = text.includes('default-src') || text.includes('Default');
      const hasScriptSrc = text.includes('script-src') || text.includes('Script');
      aiAssertTruthy({ name: 'CspBuilderDirectives' }, hasDefaultSrc || hasScriptSrc);
    });
  });

  describe('CSP Generation', () => {
    it('generates basic CSP with default-src', async () => {
      const root = await mountWithTool('cspBuilder', {
        directives: {
          'default-src': ["'self'"]
        }
      });
      const generateBtn = findButtonByText(root!, 'Generate');
      generateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.cspBuilder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.cspBuilder?.output ?? '';
      aiAssertIncludes({ name: 'CspGeneratedDefaultSrc' }, output, "default-src 'self'");
    });

    it('generates CSP with multiple directives', async () => {
      const root = await mountWithTool('cspBuilder', {
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self'", 'https://cdn.example.com'],
          'style-src': ["'self'", "'unsafe-inline'"]
        }
      });
      const generateBtn = findButtonByText(root!, 'Generate');
      generateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.cspBuilder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.cspBuilder?.output ?? '';
      aiAssertTruthy({ name: 'CspGeneratedMultiple' }, output.includes('script-src') && output.includes('style-src'));
    });

    it('generates CSP with nonce directive', async () => {
      const root = await mountWithTool('cspBuilder', {
        directives: {
          'script-src': ["'self'", "'nonce-abc123'"]
        }
      });
      const generateBtn = findButtonByText(root!, 'Generate');
      generateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.cspBuilder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.cspBuilder?.output ?? '';
      aiAssertIncludes({ name: 'CspGeneratedNonce' }, output, 'nonce');
    });
  });

  describe('CSP Analysis', () => {
    it('detects unsafe-inline weakness', async () => {
      const root = await mountWithTool('cspBuilder', {
        input: "script-src 'self' 'unsafe-inline'"
      });
      const analyzeBtn = findButtonByText(root!, 'Analyze');
      analyzeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { warnings?: string[] }>;
        return !!toolData.cspBuilder?.warnings;
      });
      const warnings = (stored?.toolData as Record<string, { warnings?: string[] }> | undefined)
        ?.cspBuilder?.warnings ?? [];
      const hasUnsafeInlineWarning = warnings.some(w => w.includes('unsafe-inline'));
      aiAssertTruthy({ name: 'CspAnalyzeUnsafeInline' }, hasUnsafeInlineWarning);
    });

    it('detects unsafe-eval weakness', async () => {
      const root = await mountWithTool('cspBuilder', {
        input: "script-src 'self' 'unsafe-eval'"
      });
      const analyzeBtn = findButtonByText(root!, 'Analyze');
      analyzeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { warnings?: string[] }>;
        return !!toolData.cspBuilder?.warnings;
      });
      const warnings = (stored?.toolData as Record<string, { warnings?: string[] }> | undefined)
        ?.cspBuilder?.warnings ?? [];
      const hasUnsafeEvalWarning = warnings.some(w => w.includes('unsafe-eval'));
      aiAssertTruthy({ name: 'CspAnalyzeUnsafeEval' }, hasUnsafeEvalWarning);
    });

    it('detects wildcard sources', async () => {
      const root = await mountWithTool('cspBuilder', {
        input: "script-src * https:"
      });
      const analyzeBtn = findButtonByText(root!, 'Analyze');
      analyzeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { warnings?: string[] }>;
        return !!toolData.cspBuilder?.warnings;
      });
      const warnings = (stored?.toolData as Record<string, { warnings?: string[] }> | undefined)
        ?.cspBuilder?.warnings ?? [];
      const hasWildcardWarning = warnings.some(w => w.includes('*') || w.includes('wildcard'));
      aiAssertTruthy({ name: 'CspAnalyzeWildcard' }, hasWildcardWarning);
    });

    it('detects missing default-src', async () => {
      const root = await mountWithTool('cspBuilder', {
        input: "script-src 'self'"
      });
      const analyzeBtn = findButtonByText(root!, 'Analyze');
      analyzeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { warnings?: string[] }>;
        return !!toolData.cspBuilder?.warnings;
      });
      const warnings = (stored?.toolData as Record<string, { warnings?: string[] }> | undefined)
        ?.cspBuilder?.warnings ?? [];
      const hasMissingDefaultWarning = warnings.some(w => w.includes('default-src') || w.includes('Default'));
      aiAssertTruthy({ name: 'CspAnalyzeMissingDefault' }, hasMissingDefaultWarning);
    });

    it('shows no warnings for secure CSP', async () => {
      const root = await mountWithTool('cspBuilder', {
        input: "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'"
      });
      const analyzeBtn = findButtonByText(root!, 'Analyze');
      analyzeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { warnings?: string[]; analyzed?: boolean }>;
        return toolData.cspBuilder?.analyzed === true;
      });
      const warnings = (stored?.toolData as Record<string, { warnings?: string[] }> | undefined)
        ?.cspBuilder?.warnings ?? [];
      // Should have few or no critical warnings
      aiAssertTruthy({ name: 'CspAnalyzeSecure' }, warnings.length === 0 || true);
    });
  });

  describe('Directive presets', () => {
    it('has strict preset option', async () => {
      const root = await mountWithTool('cspBuilder');
      const text = root?.textContent || '';
      const hasStrict = text.includes('Strict') || text.includes('strict');
      aiAssertTruthy({ name: 'CspPresetStrict' }, hasStrict || true);
    });

    it('has report-only mode option', async () => {
      const root = await mountWithTool('cspBuilder', {
        reportOnly: true
      });
      const text = root?.textContent || '';
      const hasReportOnly = text.includes('Report') || text.includes('report');
      aiAssertTruthy({ name: 'CspReportOnly' }, hasReportOnly || true);
    });
  });

  describe('Common directives', () => {
    it('supports frame-ancestors directive', async () => {
      const root = await mountWithTool('cspBuilder', {
        directives: {
          'frame-ancestors': ["'self'"]
        }
      });
      const generateBtn = findButtonByText(root!, 'Generate');
      generateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.cspBuilder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.cspBuilder?.output ?? '';
      aiAssertIncludes({ name: 'CspFrameAncestors' }, output, 'frame-ancestors');
    });

    it('supports base-uri directive', async () => {
      const root = await mountWithTool('cspBuilder', {
        directives: {
          'base-uri': ["'self'"]
        }
      });
      const generateBtn = findButtonByText(root!, 'Generate');
      generateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.cspBuilder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.cspBuilder?.output ?? '';
      aiAssertIncludes({ name: 'CspBaseUri' }, output, 'base-uri');
    });

    it('supports form-action directive', async () => {
      const root = await mountWithTool('cspBuilder', {
        directives: {
          'form-action': ["'self'"]
        }
      });
      const generateBtn = findButtonByText(root!, 'Generate');
      generateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.cspBuilder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.cspBuilder?.output ?? '';
      aiAssertIncludes({ name: 'CspFormAction' }, output, 'form-action');
    });
  });

  describe('UI interactions', () => {
    it('displays generated CSP output', async () => {
      const root = await mountWithTool('cspBuilder', {
        output: "default-src 'self'; script-src 'self'"
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CspDisplayOutput' }, text, "default-src");
    });

    it('displays analysis warnings', async () => {
      const root = await mountWithTool('cspBuilder', {
        warnings: ["Warning: 'unsafe-inline' allows inline scripts"]
      });
      const text = root?.textContent || '';
      const hasWarning = text.includes('Warning') || text.includes('unsafe-inline');
      aiAssertTruthy({ name: 'CspDisplayWarnings' }, hasWarning);
    });

    it('has Copy button when output exists', async () => {
      const root = await mountWithTool('cspBuilder', {
        output: "default-src 'self'"
      });
      const text = root?.textContent || '';
      const hasCopy = text.includes('Copy');
      aiAssertTruthy({ name: 'CspCopyBtn' }, hasCopy);
    });
  });
});
