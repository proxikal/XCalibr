/**
 * Lightweight test utilities for tool component testing.
 *
 * These utilities render components directly without mounting the full application,
 * resulting in significantly faster test execution.
 */

import React from 'react';
import { createRoot, Root } from 'react-dom/client';
import { flushSync } from 'react-dom';
import { vi } from 'vitest';

// Re-export common utilities from integration-test-utils for backward compatibility
export { resetChrome, flushPromises, waitFor } from '../../../__tests__/integration-test-utils';

/**
 * Simple container component that wraps tool components for testing.
 * Provides a minimal DOM structure similar to what tools see in production.
 */
const TestContainer: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="xcalibr-test-container" style={{ width: '400px', minHeight: '300px' }}>
    {children}
  </div>
);

// Store active roots for cleanup
const activeRoots = new Map<HTMLElement, Root>();

/**
 * Render result type for lightweight tool rendering
 */
export interface LightweightRenderResult {
  container: HTMLElement;
  getByText: (text: string) => HTMLElement | null;
  getByTestId: (testId: string) => HTMLElement | null;
  getAllByText: (text: string) => HTMLElement[];
  queryByText: (text: string) => HTMLElement | null;
  getByRole: (role: string, options?: { name?: string | RegExp }) => HTMLElement | null;
  getAllByRole: (role: string) => HTMLElement[];
  getByPlaceholder: (placeholder: string) => HTMLInputElement | HTMLTextAreaElement | null;
  findButton: (text: string) => HTMLButtonElement | null;
  findAllButtons: () => HTMLButtonElement[];
  findInput: (placeholder?: string) => HTMLInputElement | null;
  findTextarea: () => HTMLTextAreaElement | null;
  findSelect: () => HTMLSelectElement | null;
  rerender: (element: React.ReactElement) => void;
  unmount: () => void;
  debug: () => void;
}

/**
 * Lightweight render function that creates a minimal DOM for testing tool components.
 * Much faster than mountWithTool as it doesn't mount the entire application.
 * Uses React 18's createRoot API.
 */
export const renderTool = (element: React.ReactElement): LightweightRenderResult => {
  const container = document.createElement('div');
  container.id = 'test-root';
  document.body.appendChild(container);

  const root = createRoot(container);
  activeRoots.set(container, root);

  const render = (el: React.ReactElement) => {
    flushSync(() => {
      root.render(<TestContainer>{el}</TestContainer>);
    });
  };

  render(element);

  const getByText = (text: string): HTMLElement | null => {
    const elements = Array.from(container.querySelectorAll('*'));
    return elements.find(el => el.textContent?.includes(text)) as HTMLElement | null;
  };

  const getAllByText = (text: string): HTMLElement[] => {
    const elements = Array.from(container.querySelectorAll('*'));
    return elements.filter(el => el.textContent?.includes(text)) as HTMLElement[];
  };

  const queryByText = (text: string): HTMLElement | null => getByText(text);

  const getByTestId = (testId: string): HTMLElement | null => {
    return container.querySelector(`[data-testid="${testId}"]`);
  };

  const getByRole = (role: string, options?: { name?: string | RegExp }): HTMLElement | null => {
    const elements = Array.from(container.querySelectorAll(`[role="${role}"], ${role}`));
    if (!options?.name) return elements[0] as HTMLElement | null;

    return elements.find(el => {
      const text = el.textContent || el.getAttribute('aria-label') || '';
      const name = options.name;
      if (!name) return false;
      if (typeof name === 'string') {
        return text.includes(name);
      }
      return name.test(text);
    }) as HTMLElement | null;
  };

  const getAllByRole = (role: string): HTMLElement[] => {
    return Array.from(container.querySelectorAll(`[role="${role}"], ${role}`)) as HTMLElement[];
  };

  const getByPlaceholder = (placeholder: string): HTMLInputElement | HTMLTextAreaElement | null => {
    return container.querySelector(`[placeholder="${placeholder}"], [placeholder*="${placeholder}"]`);
  };

  const findButton = (text: string): HTMLButtonElement | null => {
    const buttons = Array.from(container.querySelectorAll('button'));
    return buttons.find(btn => btn.textContent?.trim() === text || btn.textContent?.includes(text)) || null;
  };

  const findAllButtons = (): HTMLButtonElement[] => {
    return Array.from(container.querySelectorAll('button'));
  };

  const findInput = (placeholder?: string): HTMLInputElement | null => {
    if (placeholder) {
      return container.querySelector(`input[placeholder*="${placeholder}"]`);
    }
    return container.querySelector('input');
  };

  const findTextarea = (): HTMLTextAreaElement | null => {
    return container.querySelector('textarea');
  };

  const findSelect = (): HTMLSelectElement | null => {
    return container.querySelector('select');
  };

  const rerender = (el: React.ReactElement) => {
    render(el);
  };

  const unmount = () => {
    const activeRoot = activeRoots.get(container);
    if (activeRoot) {
      activeRoot.unmount();
      activeRoots.delete(container);
    }
    container.remove();
  };

  const debug = () => {
    console.log('Container HTML:', container.innerHTML);
  };

  return {
    container,
    getByText,
    getByTestId,
    getAllByText,
    queryByText,
    getByRole,
    getAllByRole,
    getByPlaceholder,
    findButton,
    findAllButtons,
    findInput,
    findTextarea,
    findSelect,
    rerender,
    unmount,
    debug
  };
};

/**
 * Creates a mock onChange handler that tracks calls
 */
export const createMockOnChange = <T = unknown>() => {
  const calls: T[] = [];
  const handler = vi.fn((data: T) => {
    calls.push(data);
  });
  return {
    handler,
    calls,
    getLastCall: () => calls[calls.length - 1],
    getCalls: () => [...calls]
  };
};

/**
 * Creates a mock onRefresh handler
 */
export const createMockOnRefresh = () => {
  return vi.fn(async () => {});
};

/**
 * Simulates user input on an input or textarea element
 */
export const typeIntoInput = (
  element: HTMLInputElement | HTMLTextAreaElement,
  value: string
) => {
  element.value = value;
  element.dispatchEvent(new Event('input', { bubbles: true }));
  element.dispatchEvent(new Event('change', { bubbles: true }));
};

/**
 * Simulates a click event
 */
export const click = (element: HTMLElement) => {
  element.dispatchEvent(new MouseEvent('click', { bubbles: true }));
};

/**
 * Simulates selecting an option in a select element
 */
export const selectOption = (select: HTMLSelectElement, value: string) => {
  select.value = value;
  select.dispatchEvent(new Event('change', { bubbles: true }));
};

/**
 * Wait for an element to appear in the DOM
 */
export const waitForElement = async (
  container: HTMLElement,
  selector: string,
  timeout = 1000
): Promise<HTMLElement | null> => {
  const startTime = Date.now();
  while (Date.now() - startTime < timeout) {
    const element = container.querySelector(selector);
    if (element) return element as HTMLElement;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  return null;
};

/**
 * Assert helpers that provide better error messages
 */
export const assertExists = (element: HTMLElement | null, name: string): HTMLElement => {
  if (!element) {
    throw new Error(`Expected element "${name}" to exist in the DOM`);
  }
  return element;
};

export const assertTextContent = (element: HTMLElement, expected: string) => {
  const actual = element.textContent || '';
  if (!actual.includes(expected)) {
    throw new Error(`Expected element to contain "${expected}" but got "${actual}"`);
  }
};

/**
 * Cleanup function to be called in afterEach
 */
export const cleanup = () => {
  // Unmount all active roots
  activeRoots.forEach((root, container) => {
    root.unmount();
    container.remove();
  });
  activeRoots.clear();
  document.body.innerHTML = '';
};

/**
 * Helper to create initial tool data with defaults
 */
export const createToolData = <T extends Record<string, unknown>>(
  defaults: T,
  overrides?: Partial<T>
): T => {
  return { ...defaults, ...overrides };
};
