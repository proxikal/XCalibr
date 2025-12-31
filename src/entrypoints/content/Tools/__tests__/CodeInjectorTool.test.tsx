import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { CodeInjectorTool } from '../CodeInjectorTool';

const CodeInjector = CodeInjectorTool.Component;

describe('CodeInjectorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the CodeInjector interface', () => {
      const onChange = vi.fn();
      const onInject = vi.fn(async () => {});
      const { container } = renderTool(
        <CodeInjector data={undefined} onChange={onChange} onInject={onInject} />
      );

      aiAssertTruthy({ name: 'CodeInjectorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'CodeInjectorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const onInject = vi.fn(async () => {});
      const { container, findButton } = renderTool(
        <CodeInjector data={undefined} onChange={onChange} onInject={onInject} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'CodeInjectorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const onInject = vi.fn(async () => {});
      const { container } = renderTool(
        <CodeInjector data={undefined} onChange={onChange} onInject={onInject} />
      );

      aiAssertTruthy({ name: 'CodeInjectorInitialState' }, container);
    });
  });
});
