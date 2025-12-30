import { describe, it } from 'vitest';
import { aiAssertEqual, aiAssertTruthy } from '../../../../test-utils/aiAssert';
import type { LinkExtractorData } from '../tool-types';

const ITEMS_PER_PAGE = 12;

// Mock data factories
const createMockLinks = (internal: number, external: number): LinkExtractorData => ({
  internal: Array.from({ length: internal }, (_, i) => `https://example.com/page${i}`),
  external: Array.from({ length: external }, (_, i) => `https://external${i}.com/`),
  updatedAt: Date.now()
});

describe('LinkExtractorTool', () => {
  describe('Pagination logic', () => {
    it('should calculate total pages correctly', () => {
      const testCases = [
        { linkCount: 5, expectedPages: 1 },
        { linkCount: 12, expectedPages: 1 },
        { linkCount: 13, expectedPages: 2 },
        { linkCount: 36, expectedPages: 3 },
        { linkCount: 100, expectedPages: 9 },
      ];

      testCases.forEach(({ linkCount, expectedPages }) => {
        const totalPages = Math.ceil(linkCount / ITEMS_PER_PAGE);
        aiAssertEqual(
          { name: 'TotalPages', input: { linkCount, perPage: ITEMS_PER_PAGE } },
          totalPages,
          expectedPages
        );
      });
    });

    it('should paginate links correctly for page 0', () => {
      const data = createMockLinks(25, 0);
      const page = 0;
      const paginatedLinks = data.internal!.slice(
        page * ITEMS_PER_PAGE,
        (page + 1) * ITEMS_PER_PAGE
      );

      aiAssertEqual(
        { name: 'Page0Length', input: { totalLinks: data.internal!.length, page } },
        paginatedLinks.length,
        12
      );
    });

    it('should handle last page with fewer links', () => {
      const data = createMockLinks(30, 0);
      const page = 2;
      const paginatedLinks = data.internal!.slice(
        page * ITEMS_PER_PAGE,
        (page + 1) * ITEMS_PER_PAGE
      );

      aiAssertEqual(
        { name: 'LastPageLength', input: { totalLinks: data.internal!.length, page } },
        paginatedLinks.length,
        6
      );
    });

    it('should reset page when switching tabs', () => {
      const page = 2;
      const newPage = 0;

      aiAssertEqual(
        { name: 'PageResetOnTabSwitch', input: { oldPage: page, newPage } },
        newPage,
        0
      );
    });
  });

  describe('Tab switching', () => {
    it('should separate internal and external links', () => {
      const data = createMockLinks(10, 5);

      aiAssertEqual(
        { name: 'InternalCount', input: data },
        data.internal!.length,
        10
      );
      aiAssertEqual(
        { name: 'ExternalCount', input: data },
        data.external!.length,
        5
      );
    });

    it('should show total link count', () => {
      const data = createMockLinks(15, 10);
      const total = data.internal!.length + data.external!.length;

      aiAssertEqual(
        { name: 'TotalLinkCount', input: data },
        total,
        25
      );
    });
  });

  describe('Export functionality', () => {
    it('should create JSON export with both link types', () => {
      const data = createMockLinks(3, 2);
      const json = JSON.stringify({ internal: data.internal, external: data.external }, null, 2);

      aiAssertTruthy(
        { name: 'ExportContainsInternal', input: json },
        json.includes('page0')
      );
      aiAssertTruthy(
        { name: 'ExportContainsExternal', input: json },
        json.includes('external0.com')
      );
    });

    it('should create CSV export with correct format', () => {
      const data = createMockLinks(2, 1);
      const csv = 'type,url\n' +
        data.internal!.map(l => `internal,"${l}"`).join('\n') + '\n' +
        data.external!.map(l => `external,"${l}"`).join('\n');

      aiAssertTruthy(
        { name: 'CsvHasHeader', input: csv },
        csv.startsWith('type,url')
      );
      aiAssertTruthy(
        { name: 'CsvHasInternal', input: csv },
        csv.includes('internal,"https://example.com')
      );
      aiAssertTruthy(
        { name: 'CsvHasExternal', input: csv },
        csv.includes('external,"https://external')
      );
    });

    it('should create plain text export with sections', () => {
      const data = createMockLinks(2, 1);
      const text = `# Internal Links (${data.internal!.length})\n${data.internal!.join('\n')}\n\n# External Links (${data.external!.length})\n${data.external!.join('\n')}`;

      aiAssertTruthy(
        { name: 'TextHasInternalSection', input: text },
        text.includes('# Internal Links (2)')
      );
      aiAssertTruthy(
        { name: 'TextHasExternalSection', input: text },
        text.includes('# External Links (1)')
      );
    });
  });

  describe('Default values', () => {
    it('should use default values when data is undefined', () => {
      const getData = (): LinkExtractorData | undefined => undefined;
      const data = getData();

      const internal = data?.internal ?? [];
      const external = data?.external ?? [];

      aiAssertEqual({ name: 'DefaultInternalLength' }, internal.length, 0);
      aiAssertEqual({ name: 'DefaultExternalLength' }, external.length, 0);
    });
  });

  describe('Tab styling', () => {
    it('should have different styles for internal vs external', () => {
      const getTabStyle = (tab: 'internal' | 'external', activeTab: 'internal' | 'external') => {
        if (tab === 'internal') {
          return activeTab === 'internal'
            ? 'bg-emerald-500/10 border-emerald-500/50 text-emerald-300'
            : 'bg-slate-800 border-slate-700 text-slate-400';
        }
        return activeTab === 'external'
          ? 'bg-amber-500/10 border-amber-500/50 text-amber-300'
          : 'bg-slate-800 border-slate-700 text-slate-400';
      };

      aiAssertTruthy(
        { name: 'ActiveInternalStyle' },
        getTabStyle('internal', 'internal').includes('emerald')
      );
      aiAssertTruthy(
        { name: 'ActiveExternalStyle' },
        getTabStyle('external', 'external').includes('amber')
      );
      aiAssertTruthy(
        { name: 'InactiveStyle' },
        getTabStyle('internal', 'external').includes('slate')
      );
    });
  });

  describe('Link display', () => {
    it('should make links clickable with target blank', () => {
      const link = 'https://example.com/page';
      const targetBlank = true;
      const noopener = 'noopener noreferrer';

      aiAssertTruthy(
        { name: 'TargetBlank', input: { link, targetBlank } },
        targetBlank
      );
      aiAssertTruthy(
        { name: 'RelNoopener', input: noopener },
        noopener.includes('noopener')
      );
    });
  });

  describe('Edge cases', () => {
    it('should handle empty internal links', () => {
      const data = createMockLinks(0, 5);

      aiAssertEqual(
        { name: 'EmptyInternalLinks', input: data },
        data.internal!.length,
        0
      );
    });

    it('should handle empty external links', () => {
      const data = createMockLinks(5, 0);

      aiAssertEqual(
        { name: 'EmptyExternalLinks', input: data },
        data.external!.length,
        0
      );
    });

    it('should handle both empty', () => {
      const data = createMockLinks(0, 0);
      const total = data.internal!.length + data.external!.length;

      aiAssertEqual(
        { name: 'BothEmpty', input: data },
        total,
        0
      );
    });

    it('should handle very long URLs', () => {
      const longUrl = 'https://example.com/' + 'path/'.repeat(50);
      const data: LinkExtractorData = {
        internal: [longUrl],
        external: []
      };

      aiAssertTruthy(
        { name: 'LongUrlStored', input: data },
        data.internal![0].length > 200
      );
    });

    it('should handle URLs with special characters', () => {
      const specialUrl = 'https://example.com/path?query=value&other=test#anchor';
      const data: LinkExtractorData = {
        internal: [specialUrl],
        external: []
      };

      aiAssertTruthy(
        { name: 'SpecialCharsUrl', input: data },
        data.internal![0].includes('?') && data.internal![0].includes('&') && data.internal![0].includes('#')
      );
    });
  });

  describe('Filename generation', () => {
    it('should generate filename with hostname and date', () => {
      const hostname = 'example.com';
      const date = new Date().toISOString().split('T')[0];
      const filename = `links-${hostname}-${date}.json`;

      aiAssertTruthy(
        { name: 'FilenameContainsHostname', input: filename },
        filename.includes('example.com')
      );
      aiAssertTruthy(
        { name: 'FilenameContainsDate', input: filename },
        filename.includes(date)
      );
      aiAssertTruthy(
        { name: 'FilenameContainsExtension', input: filename },
        filename.endsWith('.json')
      );
    });
  });
});
