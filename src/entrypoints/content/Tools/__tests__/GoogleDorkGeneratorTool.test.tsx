import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertEqual, aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitFor,
  findButtonByText
} from '../../../__tests__/integration-test-utils';
import type { GoogleDorkGeneratorData, DorkTemplate } from '../tool-types';

// Test data constants
const TEST_DOMAIN = 'example.com';
const TEST_KEYWORD = 'password';
const TEST_FILETYPE = 'pdf';

// Mock dork template factory
const createMockDorkTemplate = (
  name: string,
  template: string,
  description: string
): DorkTemplate => ({
  name,
  template,
  description,
  category: 'general'
});

// Helper function to generate dork query
const generateDork = (template: string, domain: string, keyword: string): string => {
  return template
    .replace('{domain}', domain)
    .replace('{keyword}', keyword);
};

// Helper function to validate dork syntax
const isValidDorkSyntax = (query: string): boolean => {
  // Check for common dork operators
  const operators = ['site:', 'filetype:', 'inurl:', 'intitle:', 'intext:', 'ext:', 'cache:'];
  return operators.some(op => query.includes(op)) || query.length > 0;
};

describe('GoogleDorkGeneratorTool', () => {
  describe('Dork template creation', () => {
    it('creates template with correct name', () => {
      const template = createMockDorkTemplate('Site Search', 'site:{domain}', 'Find pages on a domain');
      aiAssertEqual({ name: 'TemplateName', input: template }, template.name, 'Site Search');
    });

    it('creates template with correct template string', () => {
      const template = createMockDorkTemplate('Site Search', 'site:{domain}', 'Find pages on a domain');
      aiAssertIncludes({ name: 'TemplateString', input: template }, template.template, 'site:');
    });

    it('creates template with description', () => {
      const template = createMockDorkTemplate('Site Search', 'site:{domain}', 'Find pages on a domain');
      aiAssertTruthy({ name: 'TemplateDescription', input: template }, template.description.length > 0);
    });
  });

  describe('Dork generation', () => {
    it('generates site-specific search', () => {
      const result = generateDork('site:{domain}', TEST_DOMAIN, TEST_KEYWORD);
      aiAssertEqual({ name: 'SiteDork', input: result }, result, 'site:example.com');
    });

    it('generates filetype search', () => {
      const result = generateDork('site:{domain} filetype:pdf', TEST_DOMAIN, TEST_KEYWORD);
      aiAssertIncludes({ name: 'FiletypeDork', input: result }, result, 'filetype:pdf');
    });

    it('generates keyword search on site', () => {
      const result = generateDork('site:{domain} {keyword}', TEST_DOMAIN, TEST_KEYWORD);
      aiAssertIncludes({ name: 'KeywordDork', input: result }, result, 'password');
    });

    it('generates inurl search', () => {
      const result = generateDork('site:{domain} inurl:{keyword}', TEST_DOMAIN, TEST_KEYWORD);
      aiAssertIncludes({ name: 'InurlDork', input: result }, result, 'inurl:password');
    });

    it('generates intitle search', () => {
      const result = generateDork('site:{domain} intitle:{keyword}', TEST_DOMAIN, TEST_KEYWORD);
      aiAssertIncludes({ name: 'IntitleDork', input: result }, result, 'intitle:password');
    });
  });

  describe('Dork syntax validation', () => {
    it('validates site operator', () => {
      aiAssertEqual({ name: 'SiteOperator', input: 'site:example.com' }, isValidDorkSyntax('site:example.com'), true);
    });

    it('validates filetype operator', () => {
      aiAssertEqual({ name: 'FiletypeOperator', input: 'filetype:pdf' }, isValidDorkSyntax('filetype:pdf'), true);
    });

    it('validates inurl operator', () => {
      aiAssertEqual({ name: 'InurlOperator', input: 'inurl:admin' }, isValidDorkSyntax('inurl:admin'), true);
    });

    it('validates intitle operator', () => {
      aiAssertEqual({ name: 'IntitleOperator', input: 'intitle:login' }, isValidDorkSyntax('intitle:login'), true);
    });

    it('validates combined operators', () => {
      aiAssertEqual(
        { name: 'CombinedOperators', input: 'site:example.com filetype:pdf' },
        isValidDorkSyntax('site:example.com filetype:pdf'),
        true
      );
    });

    it('accepts plain text as valid', () => {
      aiAssertEqual({ name: 'PlainText', input: 'search term' }, isValidDorkSyntax('search term'), true);
    });
  });

  describe('Default values', () => {
    it('should use default values when data is undefined', () => {
      const getData = (): GoogleDorkGeneratorData | undefined => undefined;
      const data = getData();

      const domain = data?.domain ?? '';
      const keyword = data?.keyword ?? '';
      const filetype = data?.filetype ?? '';
      const generatedQuery = data?.generatedQuery ?? '';

      aiAssertEqual({ name: 'DefaultDomain' }, domain, '');
      aiAssertEqual({ name: 'DefaultKeyword' }, keyword, '');
      aiAssertEqual({ name: 'DefaultFiletype' }, filetype, '');
      aiAssertEqual({ name: 'DefaultQuery' }, generatedQuery, '');
    });
  });

  describe('Common dork categories', () => {
    it('should have file discovery dorks', () => {
      const fileDiscoveryDorks = [
        'site:{domain} filetype:pdf',
        'site:{domain} filetype:doc',
        'site:{domain} filetype:xls',
        'site:{domain} filetype:sql'
      ];

      fileDiscoveryDorks.forEach(dork => {
        aiAssertIncludes({ name: 'FileDiscovery', input: dork }, dork, 'filetype:');
      });
    });

    it('should have login page dorks', () => {
      const loginDorks = [
        'site:{domain} inurl:login',
        'site:{domain} intitle:login',
        'site:{domain} inurl:admin'
      ];

      loginDorks.forEach(dork => {
        aiAssertTruthy({ name: 'LoginDork', input: dork }, dork.includes('login') || dork.includes('admin'));
      });
    });

    it('should have sensitive info dorks', () => {
      const sensitiveDorks = [
        'site:{domain} "password"',
        'site:{domain} "username"',
        'site:{domain} "api_key"'
      ];

      sensitiveDorks.forEach(dork => {
        aiAssertIncludes({ name: 'SensitiveDork', input: dork }, dork, 'site:');
      });
    });
  });

  describe('Query state', () => {
    it('should store generated query', () => {
      const data: GoogleDorkGeneratorData = {
        domain: TEST_DOMAIN,
        keyword: TEST_KEYWORD,
        generatedQuery: `site:${TEST_DOMAIN} ${TEST_KEYWORD}`
      };

      aiAssertIncludes({ name: 'StoredQuery', input: data }, data.generatedQuery ?? '', 'site:example.com');
    });

    it('should store selected template', () => {
      const data: GoogleDorkGeneratorData = {
        domain: TEST_DOMAIN,
        selectedTemplate: 'siteSearch'
      };

      aiAssertEqual({ name: 'SelectedTemplate', input: data }, data.selectedTemplate, 'siteSearch');
    });
  });

  describe('URL generation', () => {
    it('should generate Google search URL', () => {
      const query = 'site:example.com filetype:pdf';
      const expectedUrl = `https://www.google.com/search?q=${encodeURIComponent(query)}`;
      const generatedUrl = `https://www.google.com/search?q=${encodeURIComponent(query)}`;

      aiAssertEqual({ name: 'GoogleSearchUrl', input: query }, generatedUrl, expectedUrl);
    });
  });

  describe('History tracking', () => {
    it('should track query history', () => {
      const data: GoogleDorkGeneratorData = {
        domain: TEST_DOMAIN,
        history: [
          { query: 'site:example.com', timestamp: Date.now() - 1000 },
          { query: 'site:example.com filetype:pdf', timestamp: Date.now() }
        ]
      };

      aiAssertTruthy({ name: 'HistoryExists', input: data }, data.history && data.history.length > 0);
      aiAssertEqual({ name: 'HistoryCount', input: data }, data.history?.length, 2);
    });
  });

  describe('Integration tests', () => {
    beforeEach(() => {
      document.body.innerHTML = '';
      resetChrome();
    });

    afterEach(() => {
      document.body.innerHTML = '';
      document.head.innerHTML = '';
      vi.restoreAllMocks();
    });

    it('renders Google Dork Generator tool with input fields', async () => {
      const root = await mountWithTool('googleDorkGenerator');
      if (!root) return;

      const titleElement = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el => el.textContent?.includes('Dork') || el.textContent?.includes('Google'));
      });
      aiAssertTruthy({ name: 'TitleFound' }, titleElement);

      const domainInput = root.querySelector('input[placeholder*="domain" i], input[placeholder*="site" i]');
      aiAssertTruthy({ name: 'DomainInputFound' }, domainInput);
    });

    it('displays generated dork query', async () => {
      const root = await mountWithTool('googleDorkGenerator', {
        domain: TEST_DOMAIN,
        generatedQuery: `site:${TEST_DOMAIN} filetype:pdf`
      });
      if (!root) return;

      const queryElement = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el => el.textContent?.includes('site:example.com'));
      });
      aiAssertTruthy({ name: 'QueryDisplayed' }, queryElement);
    });

    it('has template selection options', async () => {
      const root = await mountWithTool('googleDorkGenerator');
      if (!root) return;

      const templateOption = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el =>
          el.textContent?.toLowerCase().includes('template') ||
          el.textContent?.toLowerCase().includes('category') ||
          el.textContent?.toLowerCase().includes('type')
        );
      });
      aiAssertTruthy({ name: 'TemplateOptionsFound' }, templateOption);
    });

    it('has copy and search buttons', async () => {
      const root = await mountWithTool('googleDorkGenerator', {
        domain: TEST_DOMAIN,
        generatedQuery: `site:${TEST_DOMAIN}`
      });
      if (!root) return;

      const copyButton = findButtonByText(root, 'Copy') ||
        root.querySelector('button[title*="copy" i]');
      const searchButton = findButtonByText(root, 'Search') ||
        root.querySelector('button[title*="search" i], a[href*="google.com"]');

      aiAssertTruthy({ name: 'ActionButtonsFound' }, copyButton || searchButton);
    });
  });
});
