import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertEqual, aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('HmacGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('hmacGenerator');
      aiAssertTruthy({ name: 'HmacMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'HmacTitle' }, text, 'HMAC Generator');
    });

    it('renders algorithm selector', async () => {
      const root = await mountWithTool('hmacGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'HmacSHA256' }, text, 'SHA-256');
    });

    it('renders Generate button', async () => {
      const root = await mountWithTool('hmacGenerator');
      const generateBtn = findButtonByText(root!, 'Generate');
      aiAssertTruthy({ name: 'HmacGenerateBtn' }, generateBtn);
    });

    it('renders Copy button when output exists', async () => {
      const root = await mountWithTool('hmacGenerator', {
        output: 'abc123def456'
      });
      const text = root?.textContent || '';
      const hasCopy = text.includes('Copy');
      aiAssertTruthy({ name: 'HmacCopyBtn' }, hasCopy);
    });

    it('renders message input', async () => {
      const root = await mountWithTool('hmacGenerator');
      const textarea = root?.querySelector('textarea');
      aiAssertTruthy({ name: 'HmacMessageInput' }, textarea);
    });

    it('renders key input', async () => {
      const root = await mountWithTool('hmacGenerator');
      const inputs = root?.querySelectorAll('input[type="text"]');
      // Should have at least one input for the key
      aiAssertTruthy({ name: 'HmacKeyInput' }, inputs && inputs.length > 0);
    });
  });

  describe('HMAC-SHA256 Generation', () => {
    // RFC 4231 Test Vector 1
    it('generates HMAC-SHA256 for RFC 4231 test vector 1', async () => {
      // Key: 0x0b repeated 20 times
      // Data: "Hi There"
      const root = await mountWithTool('hmacGenerator', {
        message: 'Hi There',
        key: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
        keyFormat: 'hex',
        algorithm: 'SHA-256'
      });
      const generateBtn = findButtonByText(root!, 'Generate');
      generateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.hmacGenerator?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.hmacGenerator?.output ?? '';
      aiAssertEqual({ name: 'HmacRfc4231Test1' }, output, 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
    });

    // Test with text key
    it('generates HMAC-SHA256 with text key', async () => {
      const root = await mountWithTool('hmacGenerator', {
        message: 'The quick brown fox jumps over the lazy dog',
        key: 'key',
        keyFormat: 'text',
        algorithm: 'SHA-256'
      });
      const generateBtn = findButtonByText(root!, 'Generate');
      generateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.hmacGenerator?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.hmacGenerator?.output ?? '';
      aiAssertEqual({ name: 'HmacTextKey' }, output, 'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8');
    });
  });

  describe('HMAC-SHA1 Generation', () => {
    it('generates HMAC-SHA1 with text key', async () => {
      const root = await mountWithTool('hmacGenerator', {
        message: 'The quick brown fox jumps over the lazy dog',
        key: 'key',
        keyFormat: 'text',
        algorithm: 'SHA-1'
      });
      const generateBtn = findButtonByText(root!, 'Generate');
      generateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.hmacGenerator?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.hmacGenerator?.output ?? '';
      aiAssertEqual({ name: 'HmacSha1TextKey' }, output, 'de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9');
    });
  });

  describe('HMAC-SHA512 Generation', () => {
    it('generates HMAC-SHA512 with text key', async () => {
      const root = await mountWithTool('hmacGenerator', {
        message: 'The quick brown fox jumps over the lazy dog',
        key: 'key',
        keyFormat: 'text',
        algorithm: 'SHA-512'
      });
      const generateBtn = findButtonByText(root!, 'Generate');
      generateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.hmacGenerator?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.hmacGenerator?.output ?? '';
      aiAssertEqual({ name: 'HmacSha512TextKey' }, output, 'b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a');
    });
  });

  describe('Key format handling', () => {
    it('has key format selector', async () => {
      const root = await mountWithTool('hmacGenerator');
      const text = root?.textContent || '';
      const hasText = text.includes('Text') || text.includes('text');
      const hasHex = text.includes('Hex') || text.includes('hex');
      aiAssertTruthy({ name: 'HmacKeyFormatOptions' }, hasText || hasHex);
    });

    it('shows error for invalid hex key', async () => {
      const root = await mountWithTool('hmacGenerator', {
        message: 'test',
        key: 'GHIJ', // Invalid hex
        keyFormat: 'hex',
        algorithm: 'SHA-256'
      });
      const generateBtn = findButtonByText(root!, 'Generate');
      generateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { error?: string }>;
        return !!toolData.hmacGenerator?.error;
      });
      const hasError = !!(stored?.toolData as Record<string, { error?: string }> | undefined)
        ?.hmacGenerator?.error;
      aiAssertTruthy({ name: 'HmacInvalidHexError' }, hasError);
    });
  });

  describe('Empty input handling', () => {
    it('generates HMAC for empty message', async () => {
      const root = await mountWithTool('hmacGenerator', {
        message: '',
        key: 'secret',
        keyFormat: 'text',
        algorithm: 'SHA-256'
      });
      const generateBtn = findButtonByText(root!, 'Generate');
      generateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return !!toolData.hmacGenerator?.output;
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.hmacGenerator?.output ?? '';
      // HMAC of empty message with key "secret"
      aiAssertTruthy({ name: 'HmacEmptyMessage' }, output.length === 64);
    });

    it('shows error for empty key', async () => {
      const root = await mountWithTool('hmacGenerator', {
        message: 'test',
        key: '',
        keyFormat: 'text',
        algorithm: 'SHA-256'
      });
      const generateBtn = findButtonByText(root!, 'Generate');
      generateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { error?: string }>;
        return !!toolData.hmacGenerator?.error;
      });
      const hasError = !!(stored?.toolData as Record<string, { error?: string }> | undefined)
        ?.hmacGenerator?.error;
      aiAssertTruthy({ name: 'HmacEmptyKeyError' }, hasError);
    });
  });

  describe('Output display', () => {
    it('displays HMAC output after generation', async () => {
      const root = await mountWithTool('hmacGenerator', {
        output: 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'HmacOutputDisplay' }, text, 'b0344c61');
    });
  });

  describe('UI elements', () => {
    it('has editable message textarea', async () => {
      const root = await mountWithTool('hmacGenerator');
      const textarea = root?.querySelector('textarea') as HTMLTextAreaElement;
      aiAssertTruthy({ name: 'HmacTextareaExists' }, textarea);
      aiAssertTruthy({ name: 'HmacTextareaEditable' }, !textarea?.disabled && !textarea?.readOnly);
    });

    it('displays algorithm options', async () => {
      const root = await mountWithTool('hmacGenerator');
      const text = root?.textContent || '';
      const hasSHA1 = text.includes('SHA-1');
      const hasSHA256 = text.includes('SHA-256');
      aiAssertTruthy({ name: 'HmacAlgorithmOptions' }, hasSHA1 || hasSHA256);
    });
  });
});
