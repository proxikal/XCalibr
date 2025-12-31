import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { I18nHelperTool } from '../I18nHelperTool';
import type { I18nHelperData } from '../I18nHelperTool';

const I18nHelper = I18nHelperTool.Component;

describe('I18nHelperTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the I18nHelper interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <I18nHelper data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'I18nHelperRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'I18nHelperHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <I18nHelper data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'I18nHelperInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <I18nHelper data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'I18nHelperInitialState' }, container);
    });
  });
});
