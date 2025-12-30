import { describe, it } from 'vitest';
import { aiAssertEqual } from '../../test-utils/aiAssert';
import { getAutoScrollDelta } from '../drag-tools';

describe('drag-tools', () => {
  it('scrolls up when cursor is near top edge', () => {
    const delta = getAutoScrollDelta({
      clientY: 5,
      rectTop: 0,
      rectBottom: 100,
      threshold: 20,
      speed: 8
    });
    aiAssertEqual({ name: 'AutoScrollUp' }, delta, -8);
  });

  it('scrolls down when cursor is near bottom edge', () => {
    const delta = getAutoScrollDelta({
      clientY: 95,
      rectTop: 0,
      rectBottom: 100,
      threshold: 20,
      speed: 8
    });
    aiAssertEqual({ name: 'AutoScrollDown' }, delta, 8);
  });

  it('does not scroll when cursor is in safe zone', () => {
    const delta = getAutoScrollDelta({
      clientY: 50,
      rectTop: 0,
      rectBottom: 100,
      threshold: 20,
      speed: 8
    });
    aiAssertEqual({ name: 'AutoScrollNone' }, delta, 0);
  });
});
