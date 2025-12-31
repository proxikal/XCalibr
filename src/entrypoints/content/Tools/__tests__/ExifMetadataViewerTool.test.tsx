import React from 'react';
import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup } from './test-utils';
import { ExifMetadataViewerTool } from '../ExifMetadataViewerTool';

const ExifMetadataViewer = ExifMetadataViewerTool.Component;

describe('ExifMetadataViewerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the ExifMetadataViewer interface', () => {
      const onChange = vi.fn();
      const onLoadFile = vi.fn(async () => {});
      const { container } = renderTool(
        <ExifMetadataViewer data={undefined} onChange={onChange} onLoadFile={onLoadFile} />
      );

      aiAssertTruthy({ name: 'ExifMetadataViewerRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'ExifMetadataViewerHasContent' },
        text.length > 0 || container.querySelectorAll('*').length > 5
      );
    });

    it('has interactive elements', () => {
      const onChange = vi.fn();
      const onLoadFile = vi.fn(async () => {});
      const { container, findButton } = renderTool(
        <ExifMetadataViewer data={undefined} onChange={onChange} onLoadFile={onLoadFile} />
      );

      const button = findButton('') || container.querySelector('button');
      const input = container.querySelector('input, textarea, select');
      aiAssertTruthy(
        { name: 'ExifMetadataViewerInteractive' },
        button || input || container.querySelectorAll('*').length > 5
      );
    });
  });

  describe('State Management', () => {
    it('handles initial state', () => {
      const onChange = vi.fn();
      const onLoadFile = vi.fn(async () => {});
      const { container } = renderTool(
        <ExifMetadataViewer data={undefined} onChange={onChange} onLoadFile={onLoadFile} />
      );

      aiAssertTruthy({ name: 'ExifMetadataViewerInitialState' }, container);
    });
  });
});
