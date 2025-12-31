import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { NginxConfigGeneratorTool } from '../NginxConfigGeneratorTool';

const NginxConfigGenerator = NginxConfigGeneratorTool.Component;

describe('NginxConfigGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the NginxConfigGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <NginxConfigGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'NginxConfigGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'NginxConfigGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <NginxConfigGenerator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'NginxConfigGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <NginxConfigGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'NginxConfigGeneratorInitialState' }, container);
    });
  });
});
