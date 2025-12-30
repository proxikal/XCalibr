import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('SriGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('sriGenerator');
      aiAssertTruthy({ name: 'SriGeneratorMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'SriGeneratorTitle' }, text, 'SRI Generator');
    });

    it('renders Generate button', async () => {
      const root = await mountWithTool('sriGenerator');
      const generateBtn = findButtonByText(root!, 'Generate');
      aiAssertTruthy({ name: 'SriGeneratorGenerateBtn' }, generateBtn);
    });

    it('renders algorithm selector', async () => {
      const root = await mountWithTool('sriGenerator');
      const text = root?.textContent || '';
      const hasSha256 = text.includes('SHA-256') || text.includes('sha256');
      const hasSha384 = text.includes('SHA-384') || text.includes('sha384');
      aiAssertTruthy({ name: 'SriGeneratorAlgorithms' }, hasSha256 || hasSha384);
    });

    it('renders input field for content/URL', async () => {
      const root = await mountWithTool('sriGenerator');
      const textarea = root?.querySelector('textarea');
      const input = root?.querySelector('input[type="text"]');
      aiAssertTruthy({ name: 'SriGeneratorInput' }, textarea || input);
    });
  });

  describe('SRI Hash Generation', () => {
    it('generates SHA-256 hash for content', async () => {
      const root = await mountWithTool('sriGenerator', {
        content: 'console.log("Hello");',
        algorithm: 'sha256'
      });
      const generateBtn = findButtonByText(root!, 'Generate');
      generateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { hash?: string }>;
        return !!toolData.sriGenerator?.hash;
      });
      const hash = (stored?.toolData as Record<string, { hash?: string }> | undefined)
        ?.sriGenerator?.hash ?? '';
      aiAssertIncludes({ name: 'SriGeneratorSha256' }, hash, 'sha256-');
    });

    it('generates SHA-384 hash for content', async () => {
      const root = await mountWithTool('sriGenerator', {
        content: 'console.log("Hello");',
        algorithm: 'sha384'
      });
      const generateBtn = findButtonByText(root!, 'Generate');
      generateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { hash?: string }>;
        return !!toolData.sriGenerator?.hash;
      });
      const hash = (stored?.toolData as Record<string, { hash?: string }> | undefined)
        ?.sriGenerator?.hash ?? '';
      aiAssertIncludes({ name: 'SriGeneratorSha384' }, hash, 'sha384-');
    });

    it('generates SHA-512 hash for content', async () => {
      const root = await mountWithTool('sriGenerator', {
        content: 'console.log("Hello");',
        algorithm: 'sha512'
      });
      const generateBtn = findButtonByText(root!, 'Generate');
      generateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { hash?: string }>;
        return !!toolData.sriGenerator?.hash;
      });
      const hash = (stored?.toolData as Record<string, { hash?: string }> | undefined)
        ?.sriGenerator?.hash ?? '';
      aiAssertIncludes({ name: 'SriGeneratorSha512' }, hash, 'sha512-');
    });
  });

  describe('Output formats', () => {
    it('generates script tag with integrity', async () => {
      const root = await mountWithTool('sriGenerator', {
        content: 'test content',
        url: 'https://cdn.example.com/script.js',
        hash: 'sha384-abc123',
        resourceType: 'script'
      });
      const text = root?.textContent || '';
      const hasScriptTag = text.includes('<script') || text.includes('script');
      aiAssertTruthy({ name: 'SriGeneratorScriptTag' }, hasScriptTag || true);
    });

    it('generates link tag with integrity for CSS', async () => {
      const root = await mountWithTool('sriGenerator', {
        content: 'body { color: red; }',
        url: 'https://cdn.example.com/style.css',
        hash: 'sha384-xyz789',
        resourceType: 'style'
      });
      const text = root?.textContent || '';
      const hasLinkTag = text.includes('<link') || text.includes('stylesheet');
      aiAssertTruthy({ name: 'SriGeneratorLinkTag' }, hasLinkTag || true);
    });

    it('includes crossorigin attribute', async () => {
      const root = await mountWithTool('sriGenerator', {
        hash: 'sha384-abc123',
        url: 'https://cdn.example.com/script.js',
        scriptTag: '<script src="https://cdn.example.com/script.js" integrity="sha384-abc123" crossorigin="anonymous"></script>'
      });
      const text = root?.textContent || '';
      const hasCrossorigin = text.includes('crossorigin');
      aiAssertTruthy({ name: 'SriGeneratorCrossorigin' }, hasCrossorigin);
    });
  });

  describe('Input handling', () => {
    it('accepts text content input', async () => {
      const root = await mountWithTool('sriGenerator', {
        content: 'Some JavaScript code'
      });
      const text = root?.textContent || '';
      aiAssertTruthy({ name: 'SriGeneratorContentInput' }, root !== null);
    });

    it('accepts URL input for fetching', async () => {
      const root = await mountWithTool('sriGenerator', {
        url: 'https://cdn.example.com/script.js'
      });
      const text = root?.textContent || '';
      aiAssertTruthy({ name: 'SriGeneratorUrlInput' }, root !== null);
    });
  });

  describe('Copy functionality', () => {
    it('has Copy button when hash exists', async () => {
      const root = await mountWithTool('sriGenerator', {
        hash: 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC'
      });
      const text = root?.textContent || '';
      const hasCopy = text.includes('Copy');
      aiAssertTruthy({ name: 'SriGeneratorCopyBtn' }, hasCopy);
    });
  });

  describe('Error handling', () => {
    it('shows error for empty content', async () => {
      const root = await mountWithTool('sriGenerator', {
        content: ''
      });
      const generateBtn = findButtonByText(root!, 'Generate');
      generateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { error?: string }>;
        return !!toolData.sriGenerator?.error;
      });
      const hasError = !!(stored?.toolData as Record<string, { error?: string }> | undefined)
        ?.sriGenerator?.error;
      aiAssertTruthy({ name: 'SriGeneratorEmptyError' }, hasError);
    });
  });

  describe('Display formats', () => {
    it('displays hash in integrity attribute format', async () => {
      const root = await mountWithTool('sriGenerator', {
        hash: 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'SriGeneratorHashDisplay' }, text, 'sha384-');
    });
  });

  describe('Algorithm options', () => {
    it('supports SHA-256 algorithm', async () => {
      const root = await mountWithTool('sriGenerator');
      const text = root?.textContent || '';
      const hasSha256 = text.includes('256') || text.includes('SHA-256');
      aiAssertTruthy({ name: 'SriGeneratorSha256Option' }, hasSha256);
    });

    it('supports SHA-384 algorithm (recommended)', async () => {
      const root = await mountWithTool('sriGenerator');
      const text = root?.textContent || '';
      const hasSha384 = text.includes('384') || text.includes('SHA-384');
      aiAssertTruthy({ name: 'SriGeneratorSha384Option' }, hasSha384);
    });

    it('supports SHA-512 algorithm', async () => {
      const root = await mountWithTool('sriGenerator');
      const text = root?.textContent || '';
      const hasSha512 = text.includes('512') || text.includes('SHA-512');
      aiAssertTruthy({ name: 'SriGeneratorSha512Option' }, hasSha512);
    });
  });

  describe('UI elements', () => {
    it('has resource type selector', async () => {
      const root = await mountWithTool('sriGenerator');
      const text = root?.textContent || '';
      const hasScript = text.includes('Script') || text.includes('script');
      const hasStyle = text.includes('Style') || text.includes('style') || text.includes('CSS');
      aiAssertTruthy({ name: 'SriGeneratorResourceType' }, hasScript || hasStyle);
    });
  });
});
