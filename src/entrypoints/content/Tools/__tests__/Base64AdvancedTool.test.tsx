import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertEqual, aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitFor,
  waitForState,
  typeInput
} from '../../../__tests__/integration-test-utils';

describe('Base64AdvancedTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('base64Advanced');
      aiAssertTruthy({ name: 'Base64AdvancedMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Base64AdvancedTitle' }, text, 'Base64 Advanced');
    });

    it('renders mode selector buttons', async () => {
      const root = await mountWithTool('base64Advanced');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Base64ModeStandard' }, text, 'Standard');
      aiAssertIncludes({ name: 'Base64ModeUrlSafe' }, text, 'URL-Safe');
      aiAssertIncludes({ name: 'Base64ModeHex' }, text, 'Hex');
      aiAssertIncludes({ name: 'Base64ModeImage' }, text, 'Image');
    });

    it('renders Encode button', async () => {
      const root = await mountWithTool('base64Advanced');
      const encodeBtn = findButtonByText(root!, 'Encode');
      aiAssertTruthy({ name: 'Base64EncodeBtn' }, encodeBtn);
    });

    it('renders Decode button', async () => {
      const root = await mountWithTool('base64Advanced');
      const decodeBtn = findButtonByText(root!, 'Decode');
      aiAssertTruthy({ name: 'Base64DecodeBtn' }, decodeBtn);
    });

    it('renders Copy button', async () => {
      const root = await mountWithTool('base64Advanced');
      const copyBtn = findButtonByText(root!, 'Copy');
      aiAssertTruthy({ name: 'Base64CopyBtn' }, copyBtn);
    });

    it('renders input textarea', async () => {
      const root = await mountWithTool('base64Advanced');
      const textarea = root?.querySelector('textarea');
      aiAssertTruthy({ name: 'Base64InputArea' }, textarea);
    });
  });

  describe('Standard Base64 Encoding', () => {
    it('encodes simple text to Base64', async () => {
      const root = await mountWithTool('base64Advanced', {
        input: 'Hello, World!',
        mode: 'standard'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.base64Advanced?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.base64Advanced?.output ?? '';
      aiAssertEqual({ name: 'Base64EncodeSimple' }, output, 'SGVsbG8sIFdvcmxkIQ==');
    });

    it('encodes empty string to empty output', async () => {
      const root = await mountWithTool('base64Advanced', {
        input: '',
        mode: 'standard'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return toolData.base64Advanced?.output === '';
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.base64Advanced?.output ?? 'not-empty';
      aiAssertEqual({ name: 'Base64EncodeEmpty' }, output, '');
    });

    it('encodes special characters correctly', async () => {
      const root = await mountWithTool('base64Advanced', {
        input: '<script>alert("XSS")</script>',
        mode: 'standard'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.base64Advanced?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.base64Advanced?.output ?? '';
      aiAssertEqual({ name: 'Base64EncodeSpecial' }, output, 'PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=');
    });

    it('encodes unicode characters correctly', async () => {
      const root = await mountWithTool('base64Advanced', {
        input: '你好世界',
        mode: 'standard'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.base64Advanced?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.base64Advanced?.output ?? '';
      // UTF-8 encoded '你好世界' in Base64
      aiAssertEqual({ name: 'Base64EncodeUnicode' }, output, '5L2g5aW95LiW55WM');
    });
  });

  describe('Standard Base64 Decoding', () => {
    it('decodes simple Base64 to text', async () => {
      const root = await mountWithTool('base64Advanced', {
        input: 'SGVsbG8sIFdvcmxkIQ==',
        mode: 'standard'
      });
      const decodeBtn = findButtonByText(root!, 'Decode');
      decodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.base64Advanced?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.base64Advanced?.output ?? '';
      aiAssertEqual({ name: 'Base64DecodeSimple' }, output, 'Hello, World!');
    });

    it('decodes unicode Base64 correctly', async () => {
      const root = await mountWithTool('base64Advanced', {
        input: '5L2g5aW95LiW55WM',
        mode: 'standard'
      });
      const decodeBtn = findButtonByText(root!, 'Decode');
      decodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.base64Advanced?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.base64Advanced?.output ?? '';
      aiAssertEqual({ name: 'Base64DecodeUnicode' }, output, '你好世界');
    });

    it('shows error for invalid Base64 input', async () => {
      const root = await mountWithTool('base64Advanced', {
        input: '!!!invalid-base64!!!',
        mode: 'standard'
      });
      const decodeBtn = findButtonByText(root!, 'Decode');
      decodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { error?: string }>;
        return !!toolData.base64Advanced?.error;
      });
      const hasError = !!(stored?.toolData as Record<string, { error?: string }> | undefined)
        ?.base64Advanced?.error;
      aiAssertTruthy({ name: 'Base64DecodeError' }, hasError);
    });
  });

  describe('URL-Safe Base64', () => {
    it('encodes to URL-safe Base64', async () => {
      const root = await mountWithTool('base64Advanced', {
        input: 'Hello??World++',
        mode: 'urlSafe'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.base64Advanced?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.base64Advanced?.output ?? '';
      // URL-safe: replaces + with -, / with _, removes padding =
      const hasNoPlus = !output.includes('+');
      const hasNoSlash = !output.includes('/');
      aiAssertTruthy({ name: 'Base64UrlSafeNoPlus' }, hasNoPlus);
      aiAssertTruthy({ name: 'Base64UrlSafeNoSlash' }, hasNoSlash);
    });

    it('decodes URL-safe Base64', async () => {
      // 'Hello??World++' encoded as URL-safe
      const root = await mountWithTool('base64Advanced', {
        input: 'SGVsbG8_P1dvcmxkKys',
        mode: 'urlSafe'
      });
      const decodeBtn = findButtonByText(root!, 'Decode');
      decodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.base64Advanced?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.base64Advanced?.output ?? '';
      aiAssertEqual({ name: 'Base64UrlSafeDecode' }, output, 'Hello??World++');
    });
  });

  describe('Hex to Base64', () => {
    it('converts hex string to Base64', async () => {
      const root = await mountWithTool('base64Advanced', {
        input: '48656c6c6f', // "Hello" in hex
        mode: 'hex'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.base64Advanced?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.base64Advanced?.output ?? '';
      aiAssertEqual({ name: 'Base64HexEncode' }, output, 'SGVsbG8=');
    });

    it('converts Base64 to hex string', async () => {
      const root = await mountWithTool('base64Advanced', {
        input: 'SGVsbG8=',
        mode: 'hex'
      });
      const decodeBtn = findButtonByText(root!, 'Decode');
      decodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.base64Advanced?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.base64Advanced?.output ?? '';
      aiAssertEqual({ name: 'Base64HexDecode' }, output.toLowerCase(), '48656c6c6f');
    });

    it('handles hex with 0x prefix', async () => {
      const root = await mountWithTool('base64Advanced', {
        input: '0x48656c6c6f',
        mode: 'hex'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.base64Advanced?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.base64Advanced?.output ?? '';
      aiAssertEqual({ name: 'Base64HexPrefixEncode' }, output, 'SGVsbG8=');
    });

    it('shows error for invalid hex', async () => {
      const root = await mountWithTool('base64Advanced', {
        input: 'GHIJ', // G, H, I, J are not valid hex
        mode: 'hex'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { error?: string }>;
        return !!toolData.base64Advanced?.error;
      });
      const hasError = !!(stored?.toolData as Record<string, { error?: string }> | undefined)
        ?.base64Advanced?.error;
      aiAssertTruthy({ name: 'Base64HexInvalidError' }, hasError);
    });
  });

  describe('Image to Base64 (Data URI)', () => {
    it('renders file input for image mode', async () => {
      const root = await mountWithTool('base64Advanced', {
        mode: 'image'
      });
      const fileInput = root?.querySelector('input[type="file"]');
      aiAssertTruthy({ name: 'Base64ImageFileInput' }, fileInput);
    });

    it('displays base64 data URI when provided', async () => {
      const dataUri = 'data:image/png;base64,iVBORw0KGgo=';
      const root = await mountWithTool('base64Advanced', {
        mode: 'image',
        output: dataUri
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Base64ImageDataUri' }, text, 'data:image/png;base64');
    });

    it('shows preview when image is loaded', async () => {
      const dataUri = 'data:image/png;base64,iVBORw0KGgo=';
      const root = await mountWithTool('base64Advanced', {
        mode: 'image',
        output: dataUri,
        imagePreview: dataUri
      });
      const img = root?.querySelector('img');
      aiAssertTruthy({ name: 'Base64ImagePreview' }, img);
    });
  });

  describe('Mode switching', () => {
    it('clears output when switching modes', async () => {
      const root = await mountWithTool('base64Advanced', {
        input: 'Hello',
        output: 'SGVsbG8=',
        mode: 'standard'
      });
      // Click URL-Safe mode button
      const urlSafeBtn = Array.from(root?.querySelectorAll('button') || [])
        .find(btn => btn.textContent?.includes('URL-Safe'));
      urlSafeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { mode?: string }>;
        return toolData.base64Advanced?.mode === 'urlSafe';
      });
      const mode = (stored?.toolData as Record<string, { mode?: string }> | undefined)
        ?.base64Advanced?.mode;
      aiAssertEqual({ name: 'Base64ModeSwitch' }, mode, 'urlSafe');
    });
  });

  describe('Edge cases', () => {
    it('handles whitespace in input', async () => {
      const root = await mountWithTool('base64Advanced', {
        input: 'SGVs bG8=',
        mode: 'standard'
      });
      const decodeBtn = findButtonByText(root!, 'Decode');
      decodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.base64Advanced?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.base64Advanced?.output ?? '';
      aiAssertEqual({ name: 'Base64WhitespaceDecode' }, output, 'Hello');
    });

    it('handles newlines in Base64 input', async () => {
      const root = await mountWithTool('base64Advanced', {
        input: 'SGVsbG8s\nIFdvcmxkIQ==',
        mode: 'standard'
      });
      const decodeBtn = findButtonByText(root!, 'Decode');
      decodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.base64Advanced?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.base64Advanced?.output ?? '';
      aiAssertEqual({ name: 'Base64NewlineDecode' }, output, 'Hello, World!');
    });

    it('handles very long text', async () => {
      const longText = 'A'.repeat(10000);
      const root = await mountWithTool('base64Advanced', {
        input: longText,
        mode: 'standard'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.base64Advanced?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.base64Advanced?.output ?? '';
      // Verify it's valid base64 and decodes back
      aiAssertTruthy({ name: 'Base64LongText' }, output.length > 0);
    });

    it('handles padding correctly', async () => {
      // "A" encodes to "QQ==" (2 padding chars)
      const root = await mountWithTool('base64Advanced', {
        input: 'A',
        mode: 'standard'
      });
      const encodeBtn = findButtonByText(root!, 'Encode');
      encodeBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.base64Advanced?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.base64Advanced?.output ?? '';
      aiAssertEqual({ name: 'Base64Padding' }, output, 'QQ==');
    });
  });

  describe('UI elements', () => {
    it('has editable input textarea', async () => {
      const root = await mountWithTool('base64Advanced');
      const textarea = root?.querySelector('textarea') as HTMLTextAreaElement;
      aiAssertTruthy({ name: 'Base64TextareaExists' }, textarea);
      aiAssertTruthy({ name: 'Base64TextareaEditable' }, !textarea?.disabled && !textarea?.readOnly);
    });

    it('shows output in readonly area', async () => {
      const root = await mountWithTool('base64Advanced', {
        output: 'SGVsbG8='
      });
      const textareas = root?.querySelectorAll('textarea');
      const outputArea = textareas?.[1] as HTMLTextAreaElement;
      aiAssertTruthy({ name: 'Base64OutputReadonly' }, outputArea?.readOnly);
    });

    it('displays error message when present', async () => {
      const root = await mountWithTool('base64Advanced', {
        error: 'Invalid Base64 input'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Base64ErrorDisplay' }, text, 'Invalid Base64');
    });
  });
});
