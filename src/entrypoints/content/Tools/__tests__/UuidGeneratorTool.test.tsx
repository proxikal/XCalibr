import React from 'react';
import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy, aiAssertEqual } from '../../../../test-utils/aiAssert';
import { renderTool, cleanup, createMockOnChange } from './test-utils';
import { UuidGeneratorTool } from '../UuidGeneratorTool';
import type { UuidGeneratorData } from '../UuidGeneratorTool';

const UuidGenerator = UuidGeneratorTool.Component;

describe('UUID Generator Tool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the UUID Generator interface', () => {
      const { handler } = createMockOnChange<UuidGeneratorData>();
      const { container } = renderTool(
        <UuidGenerator data={undefined} onChange={handler} />
      );

      aiAssertTruthy({ name: 'UuidGeneratorRenders' }, container);
      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'UuidGeneratorHasVersion' },
        text.includes('Version') || text.includes('UUID')
      );
    });

    it('shows generate button', () => {
      const { handler } = createMockOnChange<UuidGeneratorData>();
      const { findButton } = renderTool(
        <UuidGenerator data={undefined} onChange={handler} />
      );

      const button = findButton('Generate UUID');
      aiAssertTruthy({ name: 'UuidGeneratorButton' }, button);
    });

    it('shows version selection dropdown', () => {
      const { handler } = createMockOnChange<UuidGeneratorData>();
      const { findSelect, container } = renderTool(
        <UuidGenerator data={undefined} onChange={handler} />
      );

      const select = findSelect();
      aiAssertTruthy({ name: 'UuidGeneratorVersionSelect' }, select);

      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'UuidGeneratorHasV4Option' },
        text.includes('v4') || text.includes('Random')
      );
    });

    it('shows count input for bulk generation', () => {
      const { handler } = createMockOnChange<UuidGeneratorData>();
      const { container } = renderTool(
        <UuidGenerator data={undefined} onChange={handler} />
      );

      const text = container.textContent || '';
      const inputs = container.querySelectorAll('input[type="number"]');
      aiAssertTruthy(
        { name: 'UuidGeneratorBulkInput' },
        text.includes('Bulk') || text.includes('Count') || inputs.length >= 1
      );
    });

    it('shows uppercase toggle checkbox', () => {
      const { handler } = createMockOnChange<UuidGeneratorData>();
      const { container } = renderTool(
        <UuidGenerator data={undefined} onChange={handler} />
      );

      const checkbox = container.querySelector('input[type="checkbox"]');
      const text = container.textContent || '';
      aiAssertTruthy({ name: 'UuidGeneratorUppercase' }, checkbox);
      aiAssertTruthy({ name: 'UuidGeneratorUppercaseLabel' }, text.includes('Uppercase'));
    });
  });

  describe('Display', () => {
    it('displays generated UUID when provided', () => {
      const { handler } = createMockOnChange<UuidGeneratorData>();
      const testUuid = '550e8400-e29b-41d4-a716-446655440000';
      const { container } = renderTool(
        <UuidGenerator data={{ uuid: testUuid }} onChange={handler} />
      );

      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'UuidGeneratorOutput' },
        text.includes('550e8400') || text.includes(testUuid)
      );
    });

    it('displays bulk UUIDs when count > 1', () => {
      const { handler } = createMockOnChange<UuidGeneratorData>();
      const testUuids = [
        '550e8400-e29b-41d4-a716-446655440001',
        '550e8400-e29b-41d4-a716-446655440002',
        '550e8400-e29b-41d4-a716-446655440003'
      ];
      const { container, findButton } = renderTool(
        <UuidGenerator
          data={{ uuid: testUuids[0], uuids: testUuids }}
          onChange={handler}
        />
      );

      const text = container.textContent || '';
      aiAssertTruthy({ name: 'UuidGeneratorBulkCount' }, text.includes('3'));

      const copyAllButton = findButton('Copy All');
      aiAssertTruthy({ name: 'UuidGeneratorCopyAllButton' }, copyAllButton);
    });

    it('shows version description text', () => {
      const { handler } = createMockOnChange<UuidGeneratorData>();
      const { container } = renderTool(
        <UuidGenerator data={{ version: 'v4' }} onChange={handler} />
      );

      const text = container.textContent || '';
      aiAssertTruthy(
        { name: 'UuidGeneratorV4Description' },
        text.includes('Random') || text.includes('randomness')
      );
    });
  });

  describe('State Management', () => {
    it('uses default values when data is undefined', () => {
      const { handler } = createMockOnChange<UuidGeneratorData>();
      const { findSelect, container } = renderTool(
        <UuidGenerator data={undefined} onChange={handler} />
      );

      const select = findSelect();
      aiAssertEqual({ name: 'DefaultVersion' }, select?.value, 'v4');

      const numberInput = container.querySelector('input[type="number"]') as HTMLInputElement;
      aiAssertEqual({ name: 'DefaultCount' }, numberInput?.value, '1');
    });

    it('respects provided version value', () => {
      const { handler } = createMockOnChange<UuidGeneratorData>();
      const { findSelect } = renderTool(
        <UuidGenerator data={{ version: 'v1' }} onChange={handler} />
      );

      const select = findSelect();
      aiAssertEqual({ name: 'ProvidedVersion' }, select?.value, 'v1');
    });

    it('respects provided count value', () => {
      const { handler } = createMockOnChange<UuidGeneratorData>();
      const { container } = renderTool(
        <UuidGenerator data={{ count: 5 }} onChange={handler} />
      );

      const numberInput = container.querySelector('input[type="number"]') as HTMLInputElement;
      aiAssertEqual({ name: 'ProvidedCount' }, numberInput?.value, '5');
    });
  });

  describe('Interactions', () => {
    it('calls onChange when generate button is clicked', () => {
      const { handler, calls } = createMockOnChange<UuidGeneratorData>();
      const { findButton } = renderTool(
        <UuidGenerator data={undefined} onChange={handler} />
      );

      const button = findButton('Generate UUID');
      button?.click();

      aiAssertTruthy({ name: 'OnChangeCalledOnGenerate' }, calls.length > 0);
      aiAssertTruthy(
        { name: 'GeneratedUuidExists' },
        calls[0]?.uuid !== undefined
      );
    });

    it('generates valid UUID format', () => {
      const { handler, getLastCall } = createMockOnChange<UuidGeneratorData>();
      const { findButton } = renderTool(
        <UuidGenerator data={undefined} onChange={handler} />
      );

      const button = findButton('Generate UUID');
      button?.click();

      const lastCall = getLastCall();
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      aiAssertTruthy(
        { name: 'ValidUuidFormat', input: lastCall?.uuid },
        lastCall?.uuid && uuidRegex.test(lastCall.uuid)
      );
    });
  });
});
