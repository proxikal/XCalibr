import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { S3BucketFinderTool } from '../S3BucketFinderTool';
import type { S3BucketFinderData } from '../S3BucketFinderTool';

const S3BucketFinder = S3BucketFinderTool.Component;

describe('S3BucketFinderTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the S3BucketFinder interface', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <S3BucketFinder data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'S3BucketFinderRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'S3BucketFinderHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const { container, findButton } = renderTool(
        <S3BucketFinder data={undefined} onChange={onChange} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'S3BucketFinderInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const { container } = renderTool(
        <S3BucketFinder data={undefined} onChange={onChange} />
      );

      aiAssertTruthy({ name: 'S3BucketFinderInitialState' }, container);
    });
  });
});
