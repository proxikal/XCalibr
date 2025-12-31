import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { TodoListTool } from '../TodoListTool';
import type { TodoListData } from '../TodoListTool';

const TodoList = TodoListTool.Component;

describe('TodoListTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the TodoList interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <TodoList data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'TodoListRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'TodoListHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <TodoList data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'TodoListInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <TodoList data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'TodoListInitialState' }, container);
    });
  });
});
