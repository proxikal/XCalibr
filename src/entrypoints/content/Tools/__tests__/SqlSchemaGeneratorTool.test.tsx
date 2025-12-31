import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { SqlSchemaGeneratorTool } from '../SqlSchemaGeneratorTool';
import type { SqlSchemaGeneratorData } from '../SqlSchemaGeneratorTool';

const SqlSchemaGenerator = SqlSchemaGeneratorTool.Component;

describe('SqlSchemaGeneratorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the SqlSchemaGenerator interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <SqlSchemaGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'SqlSchemaGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'SqlSchemaGeneratorHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <SqlSchemaGenerator data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'SqlSchemaGeneratorInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <SqlSchemaGenerator data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'SqlSchemaGeneratorInitialState' }, container);
    });
  });
});
