import React from 'react';
import { describe, it, beforeEach, afterEach, vi, expect } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { AssetMapperTool } from '../AssetMapperTool';
import type { AssetMapperData, AssetEntry } from '../tool-types';

const AssetMapper = AssetMapperTool.Component;

const createMockAssets = (): AssetEntry[] => [
  { url: 'https://example.com/image.png', origin: 'https://example.com', type: 'image', sourceElement: 'img' },
  { url: 'https://example.com/script.js', origin: 'https://example.com', type: 'script', sourceElement: 'script[src]' },
  { url: 'https://cdn.example.com/style.css', origin: 'https://cdn.example.com', type: 'style', sourceElement: 'link[rel=stylesheet]' },
  { url: 'https://example.com/preload.woff2', origin: 'https://example.com', type: 'preload', sourceElement: 'link[rel=preload][as=font]' },
  { url: 'https://example.com/prefetch.js', origin: 'https://example.com', type: 'prefetch', sourceElement: 'link[rel=prefetch]' },
  { url: 'inline-script-0:console.log("test")...', origin: 'https://example.com', type: 'inline-script', size: 100, sourceElement: 'script (inline)' },
  { url: 'https://cdn.example.com/bg.jpg', origin: 'https://cdn.example.com', type: 'css-background', sourceElement: 'css url()' }
];

describe('AssetMapperTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the AssetMapper interface', () => {
      const onRefresh = vi.fn(async () => {});
      const onChange = vi.fn();
      const { container } = renderTool(
        <AssetMapper data={undefined} onChange={onChange} onRefresh={onRefresh} />
      );

      aiAssertTruthy({ name: 'AssetMapperRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'AssetMapperHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onRefresh = vi.fn(async () => {});
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <AssetMapper data={undefined} onChange={onChange} onRefresh={onRefresh} />
      );

      const button = findButton('') || container.querySelector('button');
      aiAssertTruthy({ name: 'AssetMapperInteractive' }, button);
    });

    it('displays refresh button', () => {
      const onRefresh = vi.fn(async () => {});
      const onChange = vi.fn();
      const { findButton } = renderTool(
        <AssetMapper data={undefined} onChange={onChange} onRefresh={onRefresh} />
      );

      const refreshBtn = findButton('Refresh');
      aiAssertTruthy({ name: 'RefreshButtonExists' }, refreshBtn);
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onRefresh = vi.fn(async () => {});
      const onChange = vi.fn();
      const { container } = renderTool(
        <AssetMapper data={undefined} onChange={onChange} onRefresh={onRefresh} />
      );

      aiAssertTruthy({ name: 'AssetMapperInitialState' }, container);
      expect(container.textContent).toContain('0 assets');
    });

    it('displays assets when data is provided', () => {
      const onRefresh = vi.fn(async () => {});
      const onChange = vi.fn();
      const data: AssetMapperData = {
        assets: createMockAssets(),
        updatedAt: Date.now()
      };
      const { container } = renderTool(
        <AssetMapper data={data} onChange={onChange} onRefresh={onRefresh} />
      );

      expect(container.textContent).toContain('7 assets');
    });
  });

  describe('Filtering', () => {
    it('filters assets by type', () => {
      const onRefresh = vi.fn(async () => {});
      const onChange = vi.fn();
      const data: AssetMapperData = {
        assets: createMockAssets(),
        filterType: 'image',
        updatedAt: Date.now()
      };
      const { container } = renderTool(
        <AssetMapper data={data} onChange={onChange} onRefresh={onRefresh} />
      );

      expect(container.textContent).toContain('1 assets');
      expect(container.textContent).toContain('(image)');
    });

    it('shows filter buttons for available types', () => {
      const onRefresh = vi.fn(async () => {});
      const onChange = vi.fn();
      const data: AssetMapperData = {
        assets: createMockAssets(),
        updatedAt: Date.now()
      };
      const { findButton } = renderTool(
        <AssetMapper data={data} onChange={onChange} onRefresh={onRefresh} />
      );

      // Check for type filter buttons
      expect(findButton('All')).toBeTruthy();
      expect(findButton('Images')).toBeTruthy();
      expect(findButton('Scripts')).toBeTruthy();
    });
  });

  describe('Origin Grouping', () => {
    it('shows origin filter when multiple origins exist', () => {
      const onRefresh = vi.fn(async () => {});
      const onChange = vi.fn();
      const data: AssetMapperData = {
        assets: createMockAssets(),
        updatedAt: Date.now()
      };
      const { container } = renderTool(
        <AssetMapper data={data} onChange={onChange} onRefresh={onRefresh} />
      );

      const select = container.querySelector('select');
      expect(select).toBeTruthy();
      expect(container.textContent).toContain('All Origins');
    });

    it('shows group by origin checkbox', () => {
      const onRefresh = vi.fn(async () => {});
      const onChange = vi.fn();
      const data: AssetMapperData = {
        assets: createMockAssets(),
        updatedAt: Date.now()
      };
      const { container } = renderTool(
        <AssetMapper data={data} onChange={onChange} onRefresh={onRefresh} />
      );

      expect(container.textContent).toContain('Group by origin');
    });
  });

  describe('Export', () => {
    it('shows export buttons', () => {
      const onRefresh = vi.fn(async () => {});
      const onChange = vi.fn();
      const data: AssetMapperData = {
        assets: createMockAssets(),
        updatedAt: Date.now()
      };
      const { findButton } = renderTool(
        <AssetMapper data={data} onChange={onChange} onRefresh={onRefresh} />
      );

      expect(findButton('Save as Text')).toBeTruthy();
      expect(findButton('Save as JSON')).toBeTruthy();
    });
  });

  describe('Asset Types', () => {
    it('displays inline scripts with size', () => {
      const onRefresh = vi.fn(async () => {});
      const onChange = vi.fn();
      const data: AssetMapperData = {
        assets: createMockAssets(),
        filterType: 'inline-script',
        updatedAt: Date.now()
      };
      const { container } = renderTool(
        <AssetMapper data={data} onChange={onChange} onRefresh={onRefresh} />
      );

      expect(container.textContent).toContain('inline-script');
      expect(container.textContent).toContain('100 B');
    });

    it('displays CSS background assets', () => {
      const onRefresh = vi.fn(async () => {});
      const onChange = vi.fn();
      const data: AssetMapperData = {
        assets: createMockAssets(),
        filterType: 'css-background',
        updatedAt: Date.now()
      };
      const { container } = renderTool(
        <AssetMapper data={data} onChange={onChange} onRefresh={onRefresh} />
      );

      expect(container.textContent).toContain('css-background');
      expect(container.textContent).toContain('css url()');
    });

    it('displays preload and prefetch assets', () => {
      const onRefresh = vi.fn(async () => {});
      const onChange = vi.fn();
      const data: AssetMapperData = {
        assets: createMockAssets(),
        updatedAt: Date.now()
      };
      const { container } = renderTool(
        <AssetMapper data={data} onChange={onChange} onRefresh={onRefresh} />
      );

      expect(container.textContent).toContain('Preload');
      expect(container.textContent).toContain('Prefetch');
    });
  });
});
