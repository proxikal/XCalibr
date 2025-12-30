import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertEqual, aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('HtmlEntityEncoderTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('htmlEntityEncoder');
      aiAssertTruthy({ name: 'HtmlEntityMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'HtmlEntityTitle' }, text, 'HTML Entity');
    });

    it('renders encoding mode buttons', async () => {
      const root = await mountWithTool('htmlEntityEncoder');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'HtmlEntityModeNamed' }, text, 'Named');
      aiAssertIncludes({ name: 'HtmlEntityModeDecimal' }, text, 'Decimal');
      aiAssertIncludes({ name: 'HtmlEntityModeHex' }, text, 'Hex');
    });

    it('renders Encode button', async () => {
      const root = await mountWithTool('htmlEntityEncoder');
      const encodeBtn = findButtonByText(root!, 'Encode');
      aiAssertTruthy({ name: 'HtmlEntityEncodeBtn' }, encodeBtn);
    });

    it('renders Decode button', async () => {
      const root = await mountWithTool('htmlEntityEncoder');
      const decodeBtn = findButtonByText(root!, 'Decode');
      aiAssertTruthy({ name: 'HtmlEntityDecodeBtn' }, decodeBtn);
    });

    it('renders Copy button', async () => {
      const root = await mountWithTool('htmlEntityEncoder');
      const copyBtn = findButtonByText(root!, 'Copy');
      aiAssertTruthy({ name: 'HtmlEntityCopyBtn' }, copyBtn);
    });

    it('renders input textarea', async () => {
      const root = await mountWithTool('htmlEntityEncoder');
      const textarea = root?.querySelector('textarea');
      aiAssertTruthy({ name: 'HtmlEntityInputArea' }, textarea);
    });
  });

  describe('Named Entity Encoding', () => {
    it('encodes < to &lt;', async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        input: '<',
        mode: 'named'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.htmlEntityEncoder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.htmlEntityEncoder?.output ?? '';
      aiAssertEqual({ name: 'HtmlEntityLessThan' }, output, '&lt;');
    });

    it('encodes > to &gt;', async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        input: '>',
        mode: 'named'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.htmlEntityEncoder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.htmlEntityEncoder?.output ?? '';
      aiAssertEqual({ name: 'HtmlEntityGreaterThan' }, output, '&gt;');
    });

    it('encodes & to &amp;', async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        input: '&',
        mode: 'named'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.htmlEntityEncoder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.htmlEntityEncoder?.output ?? '';
      aiAssertEqual({ name: 'HtmlEntityAmpersand' }, output, '&amp;');
    });

    it('encodes " to &quot;', async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        input: '"',
        mode: 'named'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.htmlEntityEncoder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.htmlEntityEncoder?.output ?? '';
      aiAssertEqual({ name: 'HtmlEntityQuote' }, output, '&quot;');
    });

    it("encodes ' to &#39; (single quote)", async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        input: "'",
        mode: 'named'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.htmlEntityEncoder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.htmlEntityEncoder?.output ?? '';
      // Named doesn't have apos, uses decimal fallback
      aiAssertIncludes({ name: 'HtmlEntitySingleQuote' }, output, '&#');
    });

    it('encodes XSS payload', async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        input: '<script>alert("XSS")</script>',
        mode: 'named'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.htmlEntityEncoder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.htmlEntityEncoder?.output ?? '';
      aiAssertIncludes({ name: 'HtmlEntityXSSLt' }, output, '&lt;');
      aiAssertIncludes({ name: 'HtmlEntityXSSGt' }, output, '&gt;');
      aiAssertIncludes({ name: 'HtmlEntityXSSQuot' }, output, '&quot;');
    });
  });

  describe('Decimal Entity Encoding', () => {
    it('encodes < to &#60;', async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        input: '<',
        mode: 'decimal'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.htmlEntityEncoder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.htmlEntityEncoder?.output ?? '';
      aiAssertEqual({ name: 'HtmlEntityDecimalLt' }, output, '&#60;');
    });

    it('encodes > to &#62;', async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        input: '>',
        mode: 'decimal'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.htmlEntityEncoder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.htmlEntityEncoder?.output ?? '';
      aiAssertEqual({ name: 'HtmlEntityDecimalGt' }, output, '&#62;');
    });

    it('encodes & to &#38;', async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        input: '&',
        mode: 'decimal'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.htmlEntityEncoder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.htmlEntityEncoder?.output ?? '';
      aiAssertEqual({ name: 'HtmlEntityDecimalAmp' }, output, '&#38;');
    });

    it('encodes " to &#34;', async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        input: '"',
        mode: 'decimal'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.htmlEntityEncoder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.htmlEntityEncoder?.output ?? '';
      aiAssertEqual({ name: 'HtmlEntityDecimalQuot' }, output, '&#34;');
    });

    it("encodes ' to &#39;", async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        input: "'",
        mode: 'decimal'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.htmlEntityEncoder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.htmlEntityEncoder?.output ?? '';
      aiAssertEqual({ name: 'HtmlEntityDecimalApos' }, output, '&#39;');
    });
  });

  describe('Hex Entity Encoding', () => {
    it('encodes < to &#x3c;', async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        input: '<',
        mode: 'hex'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.htmlEntityEncoder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.htmlEntityEncoder?.output ?? '';
      aiAssertEqual({ name: 'HtmlEntityHexLt' }, output, '&#x3c;');
    });

    it('encodes > to &#x3e;', async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        input: '>',
        mode: 'hex'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.htmlEntityEncoder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.htmlEntityEncoder?.output ?? '';
      aiAssertEqual({ name: 'HtmlEntityHexGt' }, output, '&#x3e;');
    });

    it('encodes & to &#x26;', async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        input: '&',
        mode: 'hex'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.htmlEntityEncoder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.htmlEntityEncoder?.output ?? '';
      aiAssertEqual({ name: 'HtmlEntityHexAmp' }, output, '&#x26;');
    });
  });

  describe('Decoding', () => {
    it('decodes &lt; to <', async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        input: '&lt;',
        mode: 'named'
      });
      const decodeBtn = findButtonByText(root!, 'Decode');
      decodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.htmlEntityEncoder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.htmlEntityEncoder?.output ?? '';
      aiAssertEqual({ name: 'HtmlEntityDecodeLt' }, output, '<');
    });

    it('decodes &#60; to <', async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        input: '&#60;',
        mode: 'decimal'
      });
      const decodeBtn = findButtonByText(root!, 'Decode');
      decodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.htmlEntityEncoder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.htmlEntityEncoder?.output ?? '';
      aiAssertEqual({ name: 'HtmlEntityDecodeDecimalLt' }, output, '<');
    });

    it('decodes &#x3c; to <', async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        input: '&#x3c;',
        mode: 'hex'
      });
      const decodeBtn = findButtonByText(root!, 'Decode');
      decodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.htmlEntityEncoder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.htmlEntityEncoder?.output ?? '';
      aiAssertEqual({ name: 'HtmlEntityDecodeHexLt' }, output, '<');
    });

    it('decodes mixed entities', async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        input: '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;',
        mode: 'named'
      });
      const decodeBtn = findButtonByText(root!, 'Decode');
      decodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.htmlEntityEncoder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.htmlEntityEncoder?.output ?? '';
      aiAssertEqual({ name: 'HtmlEntityDecodeMixed' }, output, '<script>alert("XSS")</script>');
    });
  });

  describe('Edge cases', () => {
    it('handles empty input', async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        input: '',
        mode: 'named'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return toolData.htmlEntityEncoder?.output === '';
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.htmlEntityEncoder?.output ?? 'not-empty';
      aiAssertEqual({ name: 'HtmlEntityEmpty' }, output, '');
    });

    it('preserves plain text', async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        input: 'Hello World',
        mode: 'named'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.htmlEntityEncoder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.htmlEntityEncoder?.output ?? '';
      aiAssertEqual({ name: 'HtmlEntityPlainText' }, output, 'Hello World');
    });

    it('encodes unicode characters in decimal', async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        input: '©',
        mode: 'decimal',
        encodeAll: true
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.htmlEntityEncoder?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.htmlEntityEncoder?.output ?? '';
      aiAssertEqual({ name: 'HtmlEntityCopyright' }, output, '&#169;');
    });
  });

  describe('UI elements', () => {
    it('has editable input textarea', async () => {
      const root = await mountWithTool('htmlEntityEncoder');
      const textarea = root?.querySelector('textarea') as HTMLTextAreaElement;
      aiAssertTruthy({ name: 'HtmlEntityTextareaExists' }, textarea);
      aiAssertTruthy({ name: 'HtmlEntityTextareaEditable' }, !textarea?.disabled && !textarea?.readOnly);
    });

    it('shows output in readonly area', async () => {
      const root = await mountWithTool('htmlEntityEncoder', {
        output: '&lt;test&gt;'
      });
      const textareas = root?.querySelectorAll('textarea');
      const outputArea = textareas?.[1] as HTMLTextAreaElement;
      aiAssertTruthy({ name: 'HtmlEntityOutputReadonly' }, outputArea?.readOnly);
    });

    it('displays encode all checkbox', async () => {
      const root = await mountWithTool('htmlEntityEncoder');
      const checkbox = root?.querySelector('input[type="checkbox"]');
      aiAssertTruthy({ name: 'HtmlEntityCheckbox' }, checkbox);
    });
  });
});
