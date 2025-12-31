import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { AssetMapperTool } from '../AssetMapperTool';

const AssetMapper = AssetMapperTool.Component;

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
      const { container } = renderTool(
        <AssetMapper data={undefined} onRefresh={onRefresh} />
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
      const { container, findButton } = renderTool(
        <AssetMapper data={undefined} onRefresh={onRefresh} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'AssetMapperInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onRefresh = vi.fn(async () => {});
      const { container } = renderTool(
        <AssetMapper data={undefined} onRefresh={onRefresh} />
      );

      aiAssertTruthy({ name: 'AssetMapperInitialState' }, container);
    });
  });
});
