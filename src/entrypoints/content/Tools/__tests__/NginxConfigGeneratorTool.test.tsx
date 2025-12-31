import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('NginxConfigGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('nginxConfigGenerator');
      aiAssertTruthy({ name: 'NginxMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'NginxTitle' }, text, 'Nginx Config Generator');
    });

    it('renders server name input', async () => {
      const root = await mountWithTool('nginxConfigGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'NginxServerNameLabel' }, text, 'Server Name');
    });

    it('renders port input', async () => {
      const root = await mountWithTool('nginxConfigGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'NginxPortLabel' }, text, 'Port');
    });

    it('renders SSL checkbox', async () => {
      const root = await mountWithTool('nginxConfigGenerator');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'NginxSSL' }, text, 'SSL');
    });
  });

  describe('Config Generation', () => {
    it('generates basic server block', async () => {
      const root = await mountWithTool('nginxConfigGenerator', {
        serverName: 'example.com',
        port: '80',
        root: '/var/www/html'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'NginxServerBlock' }, text, 'server');
      aiAssertIncludes({ name: 'NginxListen80' }, text, 'listen 80');
      aiAssertIncludes({ name: 'NginxServerName' }, text, 'example.com');
    });

    it('generates SSL config', async () => {
      const root = await mountWithTool('nginxConfigGenerator', {
        serverName: 'example.com',
        ssl: true
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'NginxSSLListen' }, text, '443 ssl');
      aiAssertIncludes({ name: 'NginxSSLCert' }, text, 'ssl_certificate');
    });

    it('generates proxy pass config', async () => {
      const root = await mountWithTool('nginxConfigGenerator', {
        serverName: 'example.com',
        proxyPass: 'http://localhost:3000'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'NginxProxyPass' }, text, 'proxy_pass');
      aiAssertIncludes({ name: 'NginxProxyHost' }, text, 'localhost:3000');
    });

    it('includes try_files directive', async () => {
      const root = await mountWithTool('nginxConfigGenerator', {
        serverName: 'example.com',
        root: '/var/www/html',
        proxyPass: ''
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'NginxTryFiles' }, text, 'try_files');
    });
  });

  describe('Persistence', () => {
    it('persists server name', async () => {
      const root = await mountWithTool('nginxConfigGenerator', {
        serverName: 'mysite.com'
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { serverName?: string }>;
        return toolData.nginxConfigGenerator?.serverName === 'mysite.com';
      });
      aiAssertTruthy({ name: 'NginxPersist' }, stored);
    });
  });
});
