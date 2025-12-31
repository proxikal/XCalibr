import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('HtaccessGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('htaccessGenerator');
      aiAssertTruthy({ name: 'HtaccessMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'HtaccessTitle' }, text, 'Apache .htaccess Generator');
    });

    it('renders HTTPS redirect checkbox', async () => {
      const root = await mountWithTool('htaccessGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'HtaccessHTTPS' }, text, 'HTTPS');
    });

    it('renders compression checkbox', async () => {
      const root = await mountWithTool('htaccessGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'HtaccessGzip' }, text, 'Gzip');
    });

    it('renders caching checkbox', async () => {
      const root = await mountWithTool('htaccessGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'HtaccessCaching' }, text, 'caching');
    });

    it('renders Copy button', async () => {
      const root = await mountWithTool('htaccessGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'HtaccessCopyBtn' }, text, 'Copy');
    });
  });

  describe('Config Generation', () => {
    it('generates compression rules', async () => {
      const root = await mountWithTool('htaccessGenerator', {
        compression: true,
        caching: false,
        redirects: false
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'HtaccessDeflate' }, text, 'mod_deflate');
      aiAssertIncludes({ name: 'HtaccessAddOutput' }, text, 'AddOutputFilterByType');
    });

    it('generates caching rules', async () => {
      const root = await mountWithTool('htaccessGenerator', {
        compression: false,
        caching: true,
        redirects: false
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'HtaccessExpires' }, text, 'mod_expires');
      aiAssertIncludes({ name: 'HtaccessExpiresActive' }, text, 'ExpiresActive');
    });

    it('generates HTTPS redirect rules', async () => {
      const root = await mountWithTool('htaccessGenerator', {
        compression: false,
        caching: false,
        redirects: true
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'HtaccessRewrite' }, text, 'RewriteEngine');
      aiAssertIncludes({ name: 'HtaccessHTTPSRedirect' }, text, 'https://%{HTTP_HOST}');
    });

    it('always includes security headers', async () => {
      const root = await mountWithTool('htaccessGenerator', {
        compression: false,
        caching: false,
        redirects: false
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'HtaccessXFrame' }, text, 'X-Frame-Options');
      aiAssertIncludes({ name: 'HtaccessXContent' }, text, 'X-Content-Type-Options');
    });
  });

  describe('Checkbox Interaction', () => {
    it('toggles compression', async () => {
      const root = await mountWithTool('htaccessGenerator', {
        compression: true
      });
      const checkboxes = root?.querySelectorAll('input[type="checkbox"]') as NodeListOf<HTMLInputElement>;
      const compressionBox = Array.from(checkboxes).find(cb =>
        cb.closest('label')?.textContent?.includes('Gzip')
      );
      compressionBox?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();

      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { compression?: boolean }>;
        return toolData.htaccessGenerator?.compression === false;
      });
      aiAssertTruthy({ name: 'HtaccessToggleCompression' }, stored);
    });
  });

  describe('Persistence', () => {
    it('persists checkbox states', async () => {
      const root = await mountWithTool('htaccessGenerator', {
        compression: true,
        caching: true,
        redirects: false
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { compression?: boolean; caching?: boolean }>;
        return toolData.htaccessGenerator?.compression === true && toolData.htaccessGenerator?.caching === true;
      });
      aiAssertTruthy({ name: 'HtaccessPersist' }, stored);
    });
  });
});
