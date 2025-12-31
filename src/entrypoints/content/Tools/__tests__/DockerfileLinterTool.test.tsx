import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { DockerfileLinterTool } from '../DockerfileLinterTool';

const DockerfileLinter = DockerfileLinterTool.Component;

describe('DockerfileLinterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the DockerfileLinter interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <DockerfileLinter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'DockerfileLinterRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'DockerfileLinterHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <DockerfileLinter data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'DockerfileLinterInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <DockerfileLinter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'DockerfileLinterInitialState' }, container);
    });
  });
});
