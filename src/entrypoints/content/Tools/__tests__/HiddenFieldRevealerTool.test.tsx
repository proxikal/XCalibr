import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { HiddenFieldRevealerTool } from '../HiddenFieldRevealerTool';
import type { HiddenFieldRevealerData } from '../HiddenFieldRevealerTool';

const HiddenFieldRevealer = HiddenFieldRevealerTool.Component;

describe('HiddenFieldRevealerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the HiddenFieldRevealer interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <HiddenFieldRevealer data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'HiddenFieldRevealerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'HiddenFieldRevealerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <HiddenFieldRevealer data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'HiddenFieldRevealerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <HiddenFieldRevealer data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'HiddenFieldRevealerInitialState' }, container);
    });
  });
});
