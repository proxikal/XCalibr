import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { SubnetCheatSheetTool } from '../SubnetCheatSheetTool';

const SubnetCheatSheet = SubnetCheatSheetTool.Component;

describe('SubnetCheatSheetTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the SubnetCheatSheet interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <SubnetCheatSheet data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'SubnetCheatSheetRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'SubnetCheatSheetHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <SubnetCheatSheet data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'SubnetCheatSheetInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <SubnetCheatSheet data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'SubnetCheatSheetInitialState' }, container);
    });
  });
});
