import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes, aiAssertEqual } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('YamlValidatorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('yamlValidator');
      aiAssertTruthy({ name: 'YamlMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'YamlTitle' }, text, 'YAML Validator');
    });

    it('renders Validate YAML button', async () => {
      const root = await mountWithTool('yamlValidator');
      const validateBtn = findButtonByText(root!, 'Validate YAML');
      aiAssertTruthy({ name: 'YamlValidateBtn' }, validateBtn);
    });

    it('renders textarea', async () => {
      const root = await mountWithTool('yamlValidator');
      const textarea = root?.querySelector('textarea');
      aiAssertTruthy({ name: 'YamlTextarea' }, textarea);
    });
  });

  describe('Valid YAML', () => {
    it('validates correct YAML', async () => {
      const validYaml = `name: my-app
version: 1.0.0
config:
  port: 3000
  debug: true`;

      const root = await mountWithTool('yamlValidator', {
        input: validYaml
      });
      const validateBtn = findButtonByText(root!, 'Validate YAML');
      validateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { valid?: boolean }>;
        return toolData.yamlValidator?.valid === true;
      });
      aiAssertTruthy({ name: 'YamlValid' }, stored);
    });

    it('validates YAML with arrays', async () => {
      const validYaml = `items:
  - name: item1
  - name: item2`;

      const root = await mountWithTool('yamlValidator', {
        input: validYaml
      });
      const validateBtn = findButtonByText(root!, 'Validate YAML');
      validateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { valid?: boolean }>;
        return toolData.yamlValidator?.valid === true;
      });
      aiAssertTruthy({ name: 'YamlArrayValid' }, stored);
    });
  });

  describe('Invalid YAML', () => {
    it('detects tabs in YAML', async () => {
      const invalidYaml = "name: test\n\tvalue: bad";

      const root = await mountWithTool('yamlValidator', {
        input: invalidYaml
      });
      const validateBtn = findButtonByText(root!, 'Validate YAML');
      validateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { valid?: boolean; error?: string }>;
        return toolData.yamlValidator?.valid === false;
      });
      const data = (stored?.toolData as Record<string, { valid?: boolean; error?: string }> | undefined)
        ?.yamlValidator;
      aiAssertEqual({ name: 'YamlTabsInvalid' }, data?.valid, false);
      aiAssertTruthy({ name: 'YamlTabsError' }, data?.error?.toLowerCase().includes('tab'));
    });

    it('detects missing space after colon', async () => {
      const invalidYaml = "name:value";

      const root = await mountWithTool('yamlValidator', {
        input: invalidYaml
      });
      const validateBtn = findButtonByText(root!, 'Validate YAML');
      validateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { valid?: boolean }>;
        return toolData.yamlValidator?.valid === false;
      });
      aiAssertTruthy({ name: 'YamlColonInvalid' }, stored);
    });

    it('detects empty input', async () => {
      const root = await mountWithTool('yamlValidator', {
        input: ''
      });
      const validateBtn = findButtonByText(root!, 'Validate YAML');
      validateBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { valid?: boolean }>;
        return toolData.yamlValidator?.valid === false;
      });
      aiAssertTruthy({ name: 'YamlEmptyInvalid' }, stored);
    });
  });

  describe('Persistence', () => {
    it('persists input', async () => {
      const root = await mountWithTool('yamlValidator', {
        input: 'key: value'
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { input?: string }>;
        return toolData.yamlValidator?.input === 'key: value';
      });
      aiAssertTruthy({ name: 'YamlPersist' }, stored);
    });
  });
});
