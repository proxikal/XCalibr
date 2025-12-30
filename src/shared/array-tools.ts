export const clampIndex = (value: number, max: number) => {
  if (Number.isNaN(value)) return 0;
  return Math.min(Math.max(value, 0), Math.max(0, max));
};

export const moveItem = <T,>(items: T[], fromIndex: number, toIndex: number) => {
  if (!Array.isArray(items) || items.length === 0) return items;
  const maxIndex = items.length - 1;
  const from = clampIndex(fromIndex, maxIndex);
  const to = clampIndex(toIndex, maxIndex);
  if (from === to) return items;
  const next = [...items];
  const [item] = next.splice(from, 1);
  next.splice(to, 0, item);
  return next;
};

export const moveItemAcrossPages = <T,>(
  items: T[],
  fromPage: number,
  fromIndex: number,
  toPage: number,
  toIndex: number,
  pageSize: number
) => {
  if (!Array.isArray(items) || items.length === 0) return items;
  const size = Math.max(1, pageSize);
  const fromGlobal = fromPage * size + fromIndex;
  const toGlobal = toPage * size + toIndex;
  return moveItem(items, fromGlobal, toGlobal);
};
