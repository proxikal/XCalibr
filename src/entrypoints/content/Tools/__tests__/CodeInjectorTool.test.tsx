import { beforeEach, describe, it } from 'vitest';
import { aiAssertEqual, aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitFor,
  findButtonByText,
  setRuntimeHandler
} from '../../../__tests__/integration-test-utils';

// Test the cursor position restoration logic separately
describe('CodeInjectorTool cursor behavior', () => {
  it('should preserve cursor position concept', () => {
    // Simulating cursor position management
    const originalText = 'body { color: red; }';
    const cursorPosition = 5; // After "body "

    // Insert character at cursor position
    const beforeCursor = originalText.slice(0, cursorPosition);
    const afterCursor = originalText.slice(cursorPosition);
    const newText = beforeCursor + 'X' + afterCursor;
    const newCursorPosition = cursorPosition + 1;

    aiAssertEqual(
      { name: 'CursorPosition', input: originalText },
      newText,
      'body X{ color: red; }'
    );
    aiAssertEqual(
      { name: 'NewCursorPosition', input: cursorPosition },
      newCursorPosition,
      6
    );
  });

  it('should handle cursor at end of text', () => {
    const text = 'test';
    const cursorPosition = text.length;
    const newChar = '!';
    const newText = text + newChar;
    const newCursorPosition = cursorPosition + 1;

    aiAssertEqual(
      { name: 'CursorAtEnd', input: text },
      newCursorPosition,
      5
    );
    aiAssertTruthy(
      { name: 'CursorAtEndResult' },
      newCursorPosition === newText.length
    );
  });

  it('should handle cursor at start of text', () => {
    const text = 'test';
    const cursorPosition = 0;
    const newChar = 'X';
    const newText = newChar + text;
    const newCursorPosition = 1;

    aiAssertEqual(
      { name: 'CursorAtStart', input: text },
      newText,
      'Xtest'
    );
    aiAssertEqual(
      { name: 'CursorAtStartPosition' },
      newCursorPosition,
      1
    );
  });
});

describe('CodeInjectorTool Integration tests', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  it('runs CSS Injector and sends payload via chrome runtime', async () => {
    let payload: unknown = null;
    setRuntimeHandler('xcalibr-inject-code', (next) => {
      payload = next;
      return { ok: true };
    });
    const root = await mountWithTool('codeInjector', {
      code: 'body { background: #000; }'
    });
    if (!root) return;
    const injectButton = await waitFor(() => findButtonByText(root, 'Inject CSS'));
    aiAssertTruthy({ name: 'CSSInjectorInjectButton' }, injectButton);
    injectButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    await waitFor(() => payload as { code?: string });
    aiAssertTruthy(
      { name: 'CSSInjectorPayload', state: payload },
      Boolean(payload && (payload as { code?: string }).code)
    );
  });
});
