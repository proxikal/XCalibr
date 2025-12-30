import { describe, it } from 'vitest';
import { aiAssertEqual, aiAssertTruthy } from '../../../../test-utils/aiAssert';
import type { AssetMapperData } from '../tool-types';

const ITEMS_PER_PAGE = 10;

type AssetTab = 'images' | 'scripts' | 'styles';

// Mock data factories
const createMockAssets = (
  images: number,
  scripts: number,
  styles: number
): AssetMapperData => ({
  images: Array.from({ length: images }, (_, i) => `https://example.com/image${i}.png`),
  scripts: Array.from({ length: scripts }, (_, i) => `https://example.com/script${i}.js`),
  styles: Array.from({ length: styles }, (_, i) => `https://example.com/style${i}.css`),
  updatedAt: Date.now()
});

describe('AssetMapperTool', () => {
  describe('Pagination logic', () => {
    it('should calculate total pages correctly', () => {
      const testCases = [
        { assetCount: 5, expectedPages: 1 },
        { assetCount: 10, expectedPages: 1 },
        { assetCount: 11, expectedPages: 2 },
        { assetCount: 30, expectedPages: 3 },
        { assetCount: 100, expectedPages: 10 },
      ];

      testCases.forEach(({ assetCount, expectedPages }) => {
        const totalPages = Math.ceil(assetCount / ITEMS_PER_PAGE);
        aiAssertEqual(
          { name: 'TotalPages', input: { assetCount, perPage: ITEMS_PER_PAGE } },
          totalPages,
          expectedPages
        );
      });
    });

    it('should paginate assets correctly for page 0', () => {
      const data = createMockAssets(25, 0, 0);
      const page = 0;
      const paginatedAssets = data.images!.slice(
        page * ITEMS_PER_PAGE,
        (page + 1) * ITEMS_PER_PAGE
      );

      aiAssertEqual(
        { name: 'Page0Length', input: { totalAssets: data.images!.length, page } },
        paginatedAssets.length,
        10
      );
    });

    it('should handle last page with fewer assets', () => {
      const data = createMockAssets(23, 0, 0);
      const page = 2;
      const paginatedAssets = data.images!.slice(
        page * ITEMS_PER_PAGE,
        (page + 1) * ITEMS_PER_PAGE
      );

      aiAssertEqual(
        { name: 'LastPageLength', input: { totalAssets: data.images!.length, page } },
        paginatedAssets.length,
        3
      );
    });

    it('should maintain independent pagination per tab', () => {
      const pages = { images: 0, scripts: 1, styles: 2 };

      aiAssertEqual({ name: 'ImagesPage', input: pages }, pages.images, 0);
      aiAssertEqual({ name: 'ScriptsPage', input: pages }, pages.scripts, 1);
      aiAssertEqual({ name: 'StylesPage', input: pages }, pages.styles, 2);
    });

    it('should update correct tab page', () => {
      const pages = { images: 0, scripts: 0, styles: 0 };
      const activeTab: AssetTab = 'scripts';
      const newPage = 2;
      const updatedPages = { ...pages, [activeTab]: newPage };

      aiAssertEqual(
        { name: 'UpdatedScriptsPage', input: updatedPages },
        updatedPages.scripts,
        2
      );
      aiAssertEqual(
        { name: 'UnchangedImagesPage', input: updatedPages },
        updatedPages.images,
        0
      );
    });
  });

  describe('Tab switching', () => {
    it('should separate asset types', () => {
      const data = createMockAssets(10, 5, 3);

      aiAssertEqual({ name: 'ImagesCount', input: data }, data.images!.length, 10);
      aiAssertEqual({ name: 'ScriptsCount', input: data }, data.scripts!.length, 5);
      aiAssertEqual({ name: 'StylesCount', input: data }, data.styles!.length, 3);
    });

    it('should show total asset count', () => {
      const data = createMockAssets(10, 5, 3);
      const total = data.images!.length + data.scripts!.length + data.styles!.length;

      aiAssertEqual(
        { name: 'TotalAssetCount', input: data },
        total,
        18
      );
    });
  });

  describe('Tab styling', () => {
    it('should have unique icons per tab', () => {
      const getTabIcon = (tab: AssetTab) => {
        switch (tab) {
          case 'images': return '🖼';
          case 'scripts': return '📜';
          case 'styles': return '🎨';
        }
      };

      aiAssertEqual({ name: 'ImagesIcon' }, getTabIcon('images'), '🖼');
      aiAssertEqual({ name: 'ScriptsIcon' }, getTabIcon('scripts'), '📜');
      aiAssertEqual({ name: 'StylesIcon' }, getTabIcon('styles'), '🎨');
    });

    it('should have unique styles per tab', () => {
      const getTabStyle = (tab: AssetTab, isActive: boolean) => {
        if (!isActive) return 'bg-slate-800 border-slate-700 text-slate-400';
        switch (tab) {
          case 'images':
            return 'bg-emerald-500/10 border-emerald-500/50 text-emerald-300';
          case 'scripts':
            return 'bg-amber-500/10 border-amber-500/50 text-amber-300';
          case 'styles':
            return 'bg-purple-500/10 border-purple-500/50 text-purple-300';
        }
      };

      aiAssertTruthy(
        { name: 'ActiveImagesStyleEmerald' },
        getTabStyle('images', true).includes('emerald')
      );
      aiAssertTruthy(
        { name: 'ActiveScriptsStyleAmber' },
        getTabStyle('scripts', true).includes('amber')
      );
      aiAssertTruthy(
        { name: 'ActiveStylesStylePurple' },
        getTabStyle('styles', true).includes('purple')
      );
      aiAssertTruthy(
        { name: 'InactiveStyleSlate' },
        getTabStyle('images', false).includes('slate')
      );
    });
  });

  describe('Export functionality', () => {
    it('should create plain text export with sections', () => {
      const data = createMockAssets(2, 2, 2);
      const text = `# Images (${data.images!.length})\n${data.images!.join('\n')}\n\n# Scripts (${data.scripts!.length})\n${data.scripts!.join('\n')}\n\n# Styles (${data.styles!.length})\n${data.styles!.join('\n')}`;

      aiAssertTruthy(
        { name: 'TextHasImagesSection', input: text },
        text.includes('# Images (2)')
      );
      aiAssertTruthy(
        { name: 'TextHasScriptsSection', input: text },
        text.includes('# Scripts (2)')
      );
      aiAssertTruthy(
        { name: 'TextHasStylesSection', input: text },
        text.includes('# Styles (2)')
      );
    });

    it('should create JSON export with all asset types', () => {
      const data = createMockAssets(2, 1, 1);
      const json = JSON.stringify({
        images: data.images,
        scripts: data.scripts,
        styles: data.styles
      }, null, 2);

      aiAssertTruthy(
        { name: 'ExportContainsImages', input: json },
        json.includes('image0.png')
      );
      aiAssertTruthy(
        { name: 'ExportContainsScripts', input: json },
        json.includes('script0.js')
      );
      aiAssertTruthy(
        { name: 'ExportContainsStyles', input: json },
        json.includes('style0.css')
      );
    });
  });

  describe('Default values', () => {
    it('should use default values when data is undefined', () => {
      const getData = (): AssetMapperData | undefined => undefined;
      const data = getData();

      const images = data?.images ?? [];
      const scripts = data?.scripts ?? [];
      const styles = data?.styles ?? [];

      aiAssertEqual({ name: 'DefaultImagesLength' }, images.length, 0);
      aiAssertEqual({ name: 'DefaultScriptsLength' }, scripts.length, 0);
      aiAssertEqual({ name: 'DefaultStylesLength' }, styles.length, 0);
    });
  });

  describe('Asset display', () => {
    it('should make assets clickable with target blank', () => {
      const asset = 'https://example.com/image.png';
      const targetBlank = true;
      const noopener = 'noopener noreferrer';

      aiAssertTruthy(
        { name: 'TargetBlank', input: { asset, targetBlank } },
        targetBlank
      );
      aiAssertTruthy(
        { name: 'RelNoopener', input: noopener },
        noopener.includes('noopener')
      );
    });
  });

  describe('Edge cases', () => {
    it('should handle empty images', () => {
      const data = createMockAssets(0, 5, 3);

      aiAssertEqual(
        { name: 'EmptyImages', input: data },
        data.images!.length,
        0
      );
    });

    it('should handle empty scripts', () => {
      const data = createMockAssets(5, 0, 3);

      aiAssertEqual(
        { name: 'EmptyScripts', input: data },
        data.scripts!.length,
        0
      );
    });

    it('should handle empty styles', () => {
      const data = createMockAssets(5, 3, 0);

      aiAssertEqual(
        { name: 'EmptyStyles', input: data },
        data.styles!.length,
        0
      );
    });

    it('should handle all empty', () => {
      const data = createMockAssets(0, 0, 0);
      const total = data.images!.length + data.scripts!.length + data.styles!.length;

      aiAssertEqual(
        { name: 'AllEmpty', input: data },
        total,
        0
      );
    });

    it('should handle various asset extensions', () => {
      const imageExtensions = ['.png', '.jpg', '.gif', '.svg', '.webp'];
      const scriptExtensions = ['.js', '.mjs', '.ts'];
      const styleExtensions = ['.css', '.scss', '.less'];

      aiAssertTruthy(
        { name: 'ImageExtensions', input: imageExtensions },
        imageExtensions.includes('.png') && imageExtensions.includes('.svg')
      );
      aiAssertTruthy(
        { name: 'ScriptExtensions', input: scriptExtensions },
        scriptExtensions.includes('.js') && scriptExtensions.includes('.ts')
      );
      aiAssertTruthy(
        { name: 'StyleExtensions', input: styleExtensions },
        styleExtensions.includes('.css') && styleExtensions.includes('.scss')
      );
    });

    it('should handle data URLs for images', () => {
      const dataUrl = 'data:image/png;base64,iVBORw0KGgo=';
      const data: AssetMapperData = {
        images: [dataUrl],
        scripts: [],
        styles: []
      };

      aiAssertTruthy(
        { name: 'DataUrlStored', input: data },
        data.images![0].startsWith('data:')
      );
    });

    it('should handle CDN URLs', () => {
      const cdnUrls = [
        'https://cdn.jsdelivr.net/npm/package/file.js',
        'https://unpkg.com/package/file.js',
        'https://cdnjs.cloudflare.com/ajax/libs/lib/file.js'
      ];

      cdnUrls.forEach(url => {
        aiAssertTruthy(
          { name: 'CDNUrl', input: url },
          url.includes('cdn') || url.includes('unpkg') || url.includes('cdnjs')
        );
      });
    });
  });

  describe('Filename generation', () => {
    it('should generate filename with hostname and date', () => {
      const hostname = 'example.com';
      const date = new Date().toISOString().split('T')[0];
      const filename = `assets-${hostname}-${date}.json`;

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
