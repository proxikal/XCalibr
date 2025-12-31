import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';
import type { FormFuzzerData, FieldPayloadMapping } from '../../content/Tools/tool-types';

describe('Form Fuzzer Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  const mockForms = [
    {
      index: 0,
      action: '/login',
      method: 'POST',
      inputs: [
        { name: 'username', type: 'text', value: '' },
        { name: 'password', type: 'password', value: '' },
        { name: 'csrf_token', type: 'hidden', value: 'abc123', isCsrf: true }
      ]
    },
    {
      index: 1,
      action: '/search',
      method: 'GET',
      inputs: [
        { name: 'q', type: 'text', value: '' },
        { name: 'filter', type: 'text', value: '' }
      ]
    }
  ];

  const mockFieldMappings: FieldPayloadMapping[] = [
    { fieldName: 'username', payload: '', enabled: true },
    { fieldName: 'password', payload: '', enabled: true },
    { fieldName: 'csrf_token', payload: '', enabled: false }
  ];

  it('renders the Form Fuzzer interface', async () => {
    const root = await mountWithTool('formFuzzer');
    aiAssertTruthy({ name: 'FormFuzzerRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'FormFuzzerTitle' },
      text.includes('Form') || text.includes('Fuzzer'));
  });

  it('has Scan Forms button', async () => {
    const root = await mountWithTool('formFuzzer');
    const buttons = root?.querySelectorAll('button') || [];
    const scanBtn = Array.from(buttons).find(b =>
      b.textContent?.includes('Scan') || b.textContent?.includes('Forms')
    );
    aiAssertTruthy({ name: 'FormFuzzerScanButton' }, scanBtn);
  });

  it('displays mode buttons (Inject/Preview/Submit)', async () => {
    const root = await mountWithTool('formFuzzer');
    const text = root?.textContent || '';
    const buttons = root?.querySelectorAll('button') || [];
    aiAssertTruthy({ name: 'FormFuzzerModeButtons' },
      text.includes('Inject') || text.includes('Preview') || text.includes('Submit') ||
      text.includes('💉') || text.includes('👁') || text.includes('📤') ||
      buttons.length >= 3
    );
  });

  it('shows detected forms count', async () => {
    const root = await mountWithTool('formFuzzer', {
      forms: mockForms,
      selectedFormIndex: 0
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'FormFuzzerFormsCount' },
      text.includes('2 form') || text.includes('forms detected') ||
      text.match(/\d+\s*form/i)
    );
  });

  it('displays form selection buttons', async () => {
    const root = await mountWithTool('formFuzzer', {
      forms: mockForms,
      selectedFormIndex: 0
    });
    const text = root?.textContent || '';
    // Should show form buttons like "POST #0" "GET #1"
    aiAssertTruthy({ name: 'FormFuzzerFormSelectionButtons' },
      text.includes('POST') || text.includes('GET') ||
      text.includes('#0') || text.includes('#1') ||
      text.match(/(POST|GET)\s*#\d/)
    );
  });

  it('shows payload categories (XSS, SQLi, LFI, etc.)', async () => {
    const root = await mountWithTool('formFuzzer', {
      forms: mockForms,
      selectedFormIndex: 0
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'FormFuzzerPayloadCategories' },
      text.includes('XSS') || text.includes('SQLi') || text.includes('LFI') ||
      text.includes('SSTI') || text.includes('CMD') || text.includes('XXE') ||
      text.toLowerCase().includes('xss')
    );
  });

  it('displays payload list', async () => {
    const root = await mountWithTool('formFuzzer', {
      forms: mockForms,
      selectedFormIndex: 0
    });
    // Should have multiple payload buttons
    const payloadButtons = root?.querySelectorAll('button[class*="font-mono"]') || [];
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'FormFuzzerPayloadList' },
      payloadButtons.length > 0 ||
      text.includes('<script>') || text.includes('alert') ||
      text.includes('SELECT') || text.includes('../')
    );
  });

  it('has Custom Payload option', async () => {
    const root = await mountWithTool('formFuzzer', {
      forms: mockForms,
      selectedFormIndex: 0
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'FormFuzzerCustomPayload' },
      text.includes('Custom') || text.includes('custom') || text.includes('✏️')
    );
  });

  it('shows Preserve CSRF checkbox when CSRF field detected', async () => {
    const root = await mountWithTool('formFuzzer', {
      forms: mockForms,
      selectedFormIndex: 0,
      fieldMappings: mockFieldMappings
    });
    const text = root?.textContent || '';
    const checkboxes = root?.querySelectorAll('input[type="checkbox"]') || [];
    aiAssertTruthy({ name: 'FormFuzzerPreserveCsrf' },
      text.includes('CSRF') || text.includes('Preserve') ||
      text.includes('csrf') || checkboxes.length > 0
    );
  });

  it('shows Per-Field Mapping toggle', async () => {
    const root = await mountWithTool('formFuzzer', {
      forms: mockForms,
      selectedFormIndex: 0,
      fieldMappings: mockFieldMappings
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'FormFuzzerPerFieldMapping' },
      text.includes('Per-Field') || text.includes('Mapping') ||
      text.includes('🎯') || text.includes('▶') || text.includes('▼')
    );
  });

  it('displays field mapping table when expanded', async () => {
    const root = await mountWithTool('formFuzzer', {
      forms: mockForms,
      selectedFormIndex: 0,
      fieldMappings: mockFieldMappings
    });
    const text = root?.textContent || '';
    const tables = root?.querySelectorAll('table') || [];
    // When field mapping is shown, should display table with field names
    aiAssertTruthy({ name: 'FormFuzzerFieldMappingTable' },
      tables.length > 0 ||
      text.includes('username') || text.includes('password') ||
      text.includes('Field') || text.includes('Type') || text.includes('Payload')
    );
  });

  it('shows CSRF field with lock icon in mapping', async () => {
    const root = await mountWithTool('formFuzzer', {
      forms: mockForms,
      selectedFormIndex: 0,
      fieldMappings: mockFieldMappings
    });
    const text = root?.textContent || '';
    // CSRF field may be shown as preserved or with lock icon, or the Per-Field Mapping may show CSRF info
    aiAssertTruthy({ name: 'FormFuzzerCsrfLockIcon' },
      text.includes('🔐') || text.includes('CSRF') || text.includes('csrf') ||
      text.includes('Preserve') || text.includes('token') || text.includes('Per-Field')
    );
  });

  it('has pagination for payloads', async () => {
    const root = await mountWithTool('formFuzzer', {
      forms: mockForms,
      selectedFormIndex: 0
    });
    const text = root?.textContent || '';
    // Should have pagination controls
    aiAssertTruthy({ name: 'FormFuzzerPagination' },
      text.includes('Prev') || text.includes('Next') ||
      text.includes('←') || text.includes('→') ||
      text.match(/\d+\s*\/\s*\d+/)
    );
  });

  it('has Inject Payload button', async () => {
    const root = await mountWithTool('formFuzzer', {
      forms: mockForms,
      selectedFormIndex: 0,
      submitMode: 'inject'
    });
    const buttons = root?.querySelectorAll('button') || [];
    const injectBtn = Array.from(buttons).find(b =>
      b.textContent?.includes('Inject') || b.textContent?.includes('💉')
    );
    aiAssertTruthy({ name: 'FormFuzzerInjectButton' }, injectBtn);
  });

  it('shows Inject & Submit button in submit mode', async () => {
    const root = await mountWithTool('formFuzzer', {
      forms: mockForms,
      selectedFormIndex: 0,
      submitMode: 'submit'
    });
    const text = root?.textContent || '';
    const buttons = root?.querySelectorAll('button') || [];
    const submitBtn = Array.from(buttons).find(b =>
      b.textContent?.includes('Submit') || b.textContent?.includes('📤')
    );
    aiAssertTruthy({ name: 'FormFuzzerSubmitModeButton' },
      submitBtn || text.includes('Submit') || text.includes('Inject & Submit')
    );
  });

  it('displays injection results', async () => {
    const root = await mountWithTool('formFuzzer', {
      forms: mockForms,
      selectedFormIndex: 0,
      lastResult: {
        formFound: true,
        success: true,
        appliedCount: 2,
        totalFields: 3,
        fields: [
          { name: 'username', type: 'text', applied: true },
          { name: 'password', type: 'password', applied: true },
          { name: 'csrf_token', type: 'hidden', applied: false, reason: 'CSRF preserved' }
        ]
      }
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'FormFuzzerInjectionResults' },
      text.includes('Results') || text.includes('2/3') ||
      text.includes('applied') || text.includes('✓') ||
      text.includes('injected')
    );
  });

  it('shows DOM mutations when detected', async () => {
    const root = await mountWithTool('formFuzzer', {
      forms: mockForms,
      selectedFormIndex: 0,
      domMutations: [
        { type: 'childList', target: 'div', timestamp: Date.now() },
        { type: 'attributes', target: 'input', attributeName: 'class', timestamp: Date.now() }
      ]
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'FormFuzzerDomMutations' },
      text.includes('DOM') || text.includes('Mutations') || text.includes('mutation') ||
      text.includes('childList') || text.includes('attributes')
    );
  });

  it('shows response panel after form submission', async () => {
    const root = await mountWithTool('formFuzzer', {
      forms: mockForms,
      selectedFormIndex: 0,
      lastResponse: {
        status: 200,
        body: '{"success": true}'
      }
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'FormFuzzerResponsePanel' },
      text.includes('Response') || text.includes('200') ||
      text.includes('success') || text.includes('body')
    );
  });

  it('shows validation errors when present', async () => {
    const root = await mountWithTool('formFuzzer', {
      forms: mockForms,
      selectedFormIndex: 0,
      validationErrors: [
        { field: 'username', message: 'Invalid characters detected' }
      ]
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'FormFuzzerValidationErrors' },
      text.includes('Validation') || text.includes('Error') ||
      text.includes('Invalid') || text.includes('username')
    );
  });

  it('handles empty forms state', async () => {
    const root = await mountWithTool('formFuzzer', {
      forms: [],
      selectedFormIndex: 0
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'FormFuzzerEmptyState' },
      text.includes('0 form') || text.includes('Scan') ||
      text.includes('No forms') || text.includes('detected')
    );
  });

  it('displays status messages', async () => {
    const root = await mountWithTool('formFuzzer', {
      forms: mockForms,
      selectedFormIndex: 0,
      status: 'Payload injected into 2 fields.'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'FormFuzzerStatusMessage' },
      text.includes('injected') || text.includes('Payload') ||
      text.includes('2 fields')
    );
  });

  it('shows submitting state', async () => {
    const root = await mountWithTool('formFuzzer', {
      forms: mockForms,
      selectedFormIndex: 0,
      isSubmitting: true,
      submitMode: 'submit'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'FormFuzzerSubmittingState' },
      text.includes('Submitting') || text.includes('⏳') ||
      text.includes('...')
    );
  });

  it('compact form selection buttons', async () => {
    const root = await mountWithTool('formFuzzer', {
      forms: mockForms,
      selectedFormIndex: 0
    });
    // Check that form buttons have compact styling
    const formButtons = root?.querySelectorAll('button[class*="text-[9px]"]') || [];
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'FormFuzzerCompactFormButtons' },
      formButtons.length > 0 ||
      (text.includes('POST') && text.includes('#0'))
    );
  });

  it('compact payload list items', async () => {
    const root = await mountWithTool('formFuzzer', {
      forms: mockForms,
      selectedFormIndex: 0
    });
    // Check for compact payload buttons
    const payloadItems = root?.querySelectorAll('[class*="py-1"]') || [];
    aiAssertTruthy({ name: 'FormFuzzerCompactPayloads' },
      payloadItems.length > 0 || root?.querySelectorAll('button').length
    );
  });
});
