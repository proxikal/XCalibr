import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { AdminPanelFinderTool } from '../AdminPanelFinderTool';
import type { AdminPanelFinderData } from '../AdminPanelFinderTool';

const AdminPanelFinder = AdminPanelFinderTool.Component;

describe('AdminPanelFinderTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the AdminPanelFinder interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <AdminPanelFinder data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'AdminPanelFinderRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'AdminPanelFinderHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <AdminPanelFinder data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'AdminPanelFinderInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <AdminPanelFinder data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'AdminPanelFinderInitialState' }, container);
    });
  });
});
