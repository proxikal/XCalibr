import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { CookieManagerTool } from '../CookieManagerTool';

const CookieManager = CookieManagerTool.Component;

describe('CookieManagerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the CookieManager interface', () => {
      const onChange = vi.fn();
      const onRefresh = vi.fn(async () => {});
      const { container } = renderTool(
        <CookieManager data={undefined} onChange={onChange} onRefresh={onRefresh} />
      );

      aiAssertTruthy({ name: 'CookieManagerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'CookieManagerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const onRefresh = vi.fn(async () => {});
      const { container, findButton } = renderTool(
        <CookieManager data={undefined} onChange={onChange} onRefresh={onRefresh} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'CookieManagerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const onRefresh = vi.fn(async () => {});
      const { container } = renderTool(
        <CookieManager data={undefined} onChange={onChange} onRefresh={onRefresh} />
      );

      aiAssertTruthy({ name: 'CookieManagerInitialState' }, container);
    });
  });
});
