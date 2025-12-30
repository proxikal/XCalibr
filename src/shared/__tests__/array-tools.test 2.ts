import { describe, it } from 'vitest';
import { aiAssertEqual } from '../../test-utils/aiAssert';
import { moveItem, moveItemAcrossPages } from '../array-tools';

describe('array-tools', () => {
  it('moves an item within bounds', () => {
    const items = ['a', 'b', 'c', 'd'];
    const next = moveItem(items, 0, 2);
    aiAssertEqual({ name: 'MoveItemBasic' }, next, ['b', 'c', 'a', 'd']);
  });

  it('returns same order for identical indices', () => {
    const items = ['a', 'b', 'c'];
    const next = moveItem(items, 1, 1);
    aiAssertEqual({ name: 'MoveItemNoop' }, next, items);
  });

  it('clamps indices that are out of bounds', () => {
    const items = ['a', 'b', 'c'];
    const next = moveItem(items, -4, 10);
    aiAssertEqual({ name: 'MoveItemClamp' }, next, ['b', 'c', 'a']);
  });

  it('moves between paginated indices', () => {
    const items = ['a', 'b', 'c', 'd', 'e', 'f', 'g'];
    const next = moveItemAcrossPages(items, 1, 1, 0, 0, 3);
    aiAssertEqual(
      { name: 'MoveAcrossPages' },
      next,
      ['e', 'a', 'b', 'c', 'd', 'f', 'g']
    );
  });
});
