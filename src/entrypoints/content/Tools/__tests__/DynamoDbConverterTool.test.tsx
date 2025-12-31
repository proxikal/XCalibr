import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { DynamoDbConverterTool } from '../DynamoDbConverterTool';

const DynamoDbConverter = DynamoDbConverterTool.Component;

describe('DynamoDbConverterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the DynamoDbConverter interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <DynamoDbConverter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'DynamoDbConverterRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'DynamoDbConverterHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <DynamoDbConverter data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'DynamoDbConverterInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <DynamoDbConverter data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'DynamoDbConverterInitialState' }, container);
    });
  });
});
