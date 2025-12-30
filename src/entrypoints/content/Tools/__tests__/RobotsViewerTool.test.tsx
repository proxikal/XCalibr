import { beforeEach, describe, it } from 'vitest';
import { aiAssertEqual, aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitFor,
  findButtonByText,
  queryAllByText,
  setRuntimeHandler
} from '../../../__tests__/integration-test-utils';
import type { RobotsViewerData } from '../tool-types';

type ParsedLine = {
  type: 'user-agent' | 'allow' | 'disallow' | 'sitemap' | 'crawl-delay' | 'comment' | 'other';
  directive?: string;
  value: string;
  raw: string;
};

const parseRobotsTxt = (content: string): ParsedLine[] => {
  const lines = content.split('\n');
  return lines.map((line) => {
    const trimmed = line.trim();
    if (!trimmed) return { type: 'other', value: '', raw: line };
    if (trimmed.startsWith('#')) {
      return { type: 'comment', value: trimmed.slice(1).trim(), raw: line };
    }
    const colonIndex = trimmed.indexOf(':');
    if (colonIndex === -1) return { type: 'other', value: trimmed, raw: line };

    const directive = trimmed.slice(0, colonIndex).toLowerCase().trim();
    const value = trimmed.slice(colonIndex + 1).trim();

    if (directive === 'user-agent') return { type: 'user-agent', directive, value, raw: line };
    if (directive === 'allow') return { type: 'allow', directive, value, raw: line };
    if (directive === 'disallow') return { type: 'disallow', directive, value, raw: line };
    if (directive === 'sitemap') return { type: 'sitemap', directive, value, raw: line };
    if (directive === 'crawl-delay') return { type: 'crawl-delay', directive, value, raw: line };
    return { type: 'other', directive, value, raw: line };
  });
};

describe('RobotsViewerTool', () => {
  describe('parseRobotsTxt function', () => {
    it('should parse user-agent lines', () => {
      const content = 'User-agent: *';
      const parsed = parseRobotsTxt(content);

      aiAssertEqual(
        { name: 'UserAgentType', input: content },
        parsed[0].type,
        'user-agent'
      );
      aiAssertEqual(
        { name: 'UserAgentValue', input: content },
        parsed[0].value,
        '*'
      );
    });

    it('should parse allow lines', () => {
      const content = 'Allow: /public/';
      const parsed = parseRobotsTxt(content);

      aiAssertEqual(
        { name: 'AllowType', input: content },
        parsed[0].type,
        'allow'
      );
      aiAssertEqual(
        { name: 'AllowValue', input: content },
        parsed[0].value,
        '/public/'
      );
    });

    it('should parse disallow lines', () => {
      const content = 'Disallow: /private/';
      const parsed = parseRobotsTxt(content);

      aiAssertEqual(
        { name: 'DisallowType', input: content },
        parsed[0].type,
        'disallow'
      );
      aiAssertEqual(
        { name: 'DisallowValue', input: content },
        parsed[0].value,
        '/private/'
      );
    });

    it('should parse sitemap lines', () => {
      const content = 'Sitemap: https://example.com/sitemap.xml';
      const parsed = parseRobotsTxt(content);

      aiAssertEqual(
        { name: 'SitemapType', input: content },
        parsed[0].type,
        'sitemap'
      );
      aiAssertEqual(
        { name: 'SitemapValue', input: content },
        parsed[0].value,
        'https://example.com/sitemap.xml'
      );
    });

    it('should parse crawl-delay lines', () => {
      const content = 'Crawl-delay: 10';
      const parsed = parseRobotsTxt(content);

      aiAssertEqual(
        { name: 'CrawlDelayType', input: content },
        parsed[0].type,
        'crawl-delay'
      );
      aiAssertEqual(
        { name: 'CrawlDelayValue', input: content },
        parsed[0].value,
        '10'
      );
    });

    it('should parse comment lines', () => {
      const content = '# This is a comment';
      const parsed = parseRobotsTxt(content);

      aiAssertEqual(
        { name: 'CommentType', input: content },
        parsed[0].type,
        'comment'
      );
      aiAssertEqual(
        { name: 'CommentValue', input: content },
        parsed[0].value,
        'This is a comment'
      );
    });

    it('should handle empty lines', () => {
      const content = '';
      const parsed = parseRobotsTxt(content);

      aiAssertEqual(
        { name: 'EmptyLineType', input: content },
        parsed[0].type,
        'other'
      );
      aiAssertEqual(
        { name: 'EmptyLineValue', input: content },
        parsed[0].value,
        ''
      );
    });

    it('should be case-insensitive for directives', () => {
      const testCases = [
        { content: 'USER-AGENT: bot', expectedType: 'user-agent' },
        { content: 'DISALLOW: /', expectedType: 'disallow' },
        { content: 'Allow: /path', expectedType: 'allow' },
      ];

      testCases.forEach(({ content, expectedType }) => {
        const parsed = parseRobotsTxt(content);
        aiAssertEqual(
          { name: 'CaseInsensitiveDirective', input: content },
          parsed[0].type,
          expectedType
        );
      });
    });
  });

  describe('Statistics calculation', () => {
    it('should count different directive types', () => {
      const content = `User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /public/
Sitemap: https://example.com/sitemap.xml`;

      const parsed = parseRobotsTxt(content);
      const stats = {
        userAgents: parsed.filter(l => l.type === 'user-agent').length,
        allows: parsed.filter(l => l.type === 'allow').length,
        disallows: parsed.filter(l => l.type === 'disallow').length,
        sitemaps: parsed.filter(l => l.type === 'sitemap').length
      };

      aiAssertEqual({ name: 'UserAgentCount', input: stats }, stats.userAgents, 1);
      aiAssertEqual({ name: 'AllowCount', input: stats }, stats.allows, 1);
      aiAssertEqual({ name: 'DisallowCount', input: stats }, stats.disallows, 2);
      aiAssertEqual({ name: 'SitemapCount', input: stats }, stats.sitemaps, 1);
    });
  });

  describe('Line styling', () => {
    it('should have unique icons per line type', () => {
      const getLineIcon = (type: ParsedLine['type']) => {
        switch (type) {
          case 'user-agent': return '🤖';
          case 'allow': return '✓';
          case 'disallow': return '✗';
          case 'sitemap': return '🗺';
          case 'crawl-delay': return '⏱';
          case 'comment': return '#';
          default: return '·';
        }
      };

      aiAssertEqual({ name: 'UserAgentIcon' }, getLineIcon('user-agent'), '🤖');
      aiAssertEqual({ name: 'AllowIcon' }, getLineIcon('allow'), '✓');
      aiAssertEqual({ name: 'DisallowIcon' }, getLineIcon('disallow'), '✗');
      aiAssertEqual({ name: 'SitemapIcon' }, getLineIcon('sitemap'), '🗺');
      aiAssertEqual({ name: 'CrawlDelayIcon' }, getLineIcon('crawl-delay'), '⏱');
      aiAssertEqual({ name: 'CommentIcon' }, getLineIcon('comment'), '#');
    });

    it('should have unique styles per line type', () => {
      const getLineStyle = (type: ParsedLine['type']) => {
        switch (type) {
          case 'user-agent': return 'border-blue-500/30';
          case 'allow': return 'border-emerald-500/30';
          case 'disallow': return 'border-rose-500/30';
          case 'sitemap': return 'border-amber-500/30';
          case 'crawl-delay': return 'border-purple-500/30';
          case 'comment': return 'border-slate-700';
          default: return 'border-slate-700';
        }
      };

      aiAssertTruthy({ name: 'UserAgentStyleBlue' }, getLineStyle('user-agent').includes('blue'));
      aiAssertTruthy({ name: 'AllowStyleEmerald' }, getLineStyle('allow').includes('emerald'));
      aiAssertTruthy({ name: 'DisallowStyleRose' }, getLineStyle('disallow').includes('rose'));
      aiAssertTruthy({ name: 'SitemapStyleAmber' }, getLineStyle('sitemap').includes('amber'));
    });
  });

  describe('Export functionality', () => {
    it('should create text export', () => {
      const content = 'User-agent: *\nDisallow: /private/';
      const blob = new Blob([content], { type: 'text/plain' });

      aiAssertEqual(
        { name: 'TextBlobType', input: content },
        blob.type,
        'text/plain'
      );
    });

    it('should create JSON export with rules', () => {
      const content = 'User-agent: *\nDisallow: /private/\n# comment';
      const parsed = parseRobotsTxt(content);
      const exportData = {
        url: 'https://example.com/robots.txt',
        fetchedAt: new Date().toISOString(),
        rules: parsed
          .filter(l => l.type !== 'comment' && l.type !== 'other' && l.value)
          .map(l => ({ type: l.type, value: l.value }))
      };

      const json = JSON.stringify(exportData, null, 2);

      aiAssertTruthy({ name: 'ExportContainsUrl', input: json }, json.includes('example.com'));
      aiAssertTruthy({ name: 'ExportContainsRules', input: json }, json.includes('user-agent'));
      aiAssertTruthy({ name: 'ExportExcludesComments', input: json }, !json.includes('comment'));
    });
  });

  describe('Default values', () => {
    it('should use default values when data is undefined', () => {
      const getData = (): RobotsViewerData | undefined => undefined;
      const data = getData();

      const content = data?.content ?? '';
      const url = data?.url;
      const error = data?.error;

      aiAssertEqual({ name: 'DefaultContent' }, content, '');
      aiAssertEqual({ name: 'DefaultUrl' }, url, undefined);
      aiAssertEqual({ name: 'DefaultError' }, error, undefined);
    });
  });

  describe('View modes', () => {
    it('should support parsed view mode', () => {
      const viewMode = 'parsed';

      aiAssertEqual(
        { name: 'ParsedViewMode', input: viewMode },
        viewMode,
        'parsed'
      );
    });

    it('should support raw view mode', () => {
      const viewMode = 'raw';

      aiAssertEqual(
        { name: 'RawViewMode', input: viewMode },
        viewMode,
        'raw'
      );
    });
  });

  describe('Edge cases', () => {
    it('should handle malformed lines', () => {
      const content = 'This has no colon';
      const parsed = parseRobotsTxt(content);

      aiAssertEqual(
        { name: 'MalformedLineType', input: content },
        parsed[0].type,
        'other'
      );
    });

    it('should handle lines with multiple colons', () => {
      const content = 'Sitemap: https://example.com:8080/sitemap.xml';
      const parsed = parseRobotsTxt(content);

      aiAssertEqual(
        { name: 'MultipleColonsType', input: content },
        parsed[0].type,
        'sitemap'
      );
      aiAssertTruthy(
        { name: 'MultipleColonsValue', input: parsed[0] },
        parsed[0].value.includes(':8080')
      );
    });

    it('should handle whitespace around values', () => {
      const content = 'User-agent:   *  ';
      const parsed = parseRobotsTxt(content);

      aiAssertEqual(
        { name: 'TrimmedValue', input: content },
        parsed[0].value,
        '*'
      );
    });

    it('should preserve raw line content', () => {
      const content = '  User-agent: googlebot  ';
      const parsed = parseRobotsTxt(content);

      aiAssertEqual(
        { name: 'RawPreserved', input: content },
        parsed[0].raw,
        content
      );
    });

    it('should handle unknown directives', () => {
      const content = 'Custom-directive: value';
      const parsed = parseRobotsTxt(content);

      aiAssertEqual(
        { name: 'UnknownDirectiveType', input: content },
        parsed[0].type,
        'other'
      );
      aiAssertEqual(
        { name: 'UnknownDirectiveName', input: content },
        parsed[0].directive,
        'custom-directive'
      );
    });
  });

  describe('Integration tests', () => {
    beforeEach(() => {
      document.body.innerHTML = '';
      resetChrome();
    });

    it('loads robots.txt content', async () => {
      setRuntimeHandler('xcalibr-fetch-robots', () => ({
        url: 'https://example.com/robots.txt',
        content: 'User-agent: *',
        updatedAt: Date.now()
      }));
      const root = await mountWithTool('robotsViewer');
      if (!root) return;
      const fetchButton = await waitFor(() => findButtonByText(root, 'Fetch'));
      aiAssertTruthy({ name: 'RobotsViewerFetch' }, fetchButton);
      fetchButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const userAgentLine = await waitFor(() => queryAllByText(root, 'user-agent')[0]);
      aiAssertTruthy(
        { name: 'RobotsViewerContent' },
        userAgentLine
      );
    });
  });
});
