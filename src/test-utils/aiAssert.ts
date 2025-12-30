import { expect } from 'vitest';

type AiAssertContext = {
  name: string;
  input?: unknown;
  state?: unknown;
  expected?: unknown;
  actual?: unknown;
  notes?: string;
};

const serialize = (value: unknown) => {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
};

const buildMessage = (context: AiAssertContext) => {
  const parts = [
    `Function/Component: ${context.name}`,
    `Input: ${serialize(context.input)}`,
    `State: ${serialize(context.state)}`,
    `Expected: ${serialize(context.expected)}`,
    `Actual: ${serialize(context.actual)}`
  ];
  if (context.notes) parts.push(`Notes: ${context.notes}`);
  return parts.join('\n');
};

export const aiAssertEqual = (
  context: AiAssertContext,
  actual: unknown,
  expected: unknown
) => {
  expect(actual, buildMessage({ ...context, actual, expected })).toEqual(expected);
};

export const aiAssertTruthy = (context: AiAssertContext, actual: unknown) => {
  expect(Boolean(actual), buildMessage({ ...context, actual, expected: true })).toBe(true);
};

export const aiAssertIncludes = (
  context: AiAssertContext,
  actual: string,
  expected: string
) => {
  expect(actual, buildMessage({ ...context, actual, expected })).toContain(expected);
};
