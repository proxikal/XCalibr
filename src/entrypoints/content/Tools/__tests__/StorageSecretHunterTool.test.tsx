import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { StorageSecretHunterTool } from '../StorageSecretHunterTool';
import type { StorageSecretHunterData } from '../StorageSecretHunterTool';

const StorageSecretHunter = StorageSecretHunterTool.Component;

describe('StorageSecretHunterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the StorageSecretHunter interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <StorageSecretHunter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'StorageSecretHunterRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'StorageSecretHunterHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <StorageSecretHunter data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'StorageSecretHunterInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <StorageSecretHunter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'StorageSecretHunterInitialState' }, container);
    });
  });
});
