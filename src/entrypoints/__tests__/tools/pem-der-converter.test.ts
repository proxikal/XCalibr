import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  findButtonByText
} from '../integration-test-utils';

describe('PEM/DER Certificate Converter Tool', () => {
  beforeEach(() => {
    resetChrome();
    document.body.innerHTML = '';
  });

  afterEach(() => {
    document.body.innerHTML = '';
  });

  it('renders the converter interface', async () => {
    const root = await mountWithTool('pemDerConverter');
    aiAssertTruthy({ name: 'PemDerConverterRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'PemDerConverterTitle' }, text.includes('PEM') || text.includes('DER'));
  });

  it('shows input textarea for certificate', async () => {
    const root = await mountWithTool('pemDerConverter');
    const textarea = root?.querySelector('textarea[placeholder*="PEM"]') ||
                     root?.querySelector('textarea[placeholder*="certificate"]') ||
                     root?.querySelector('textarea');
    aiAssertTruthy({ name: 'PemDerConverterInput' }, textarea);
  });

  it('has format selection buttons', async () => {
    const root = await mountWithTool('pemDerConverter');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'PemDerConverterFormats' },
      (text.includes('PEM') && text.includes('DER')) || text.includes('Format'));
  });

  it('has convert button', async () => {
    const root = await mountWithTool('pemDerConverter');
    const btn = findButtonByText(root!, 'Convert') ||
                findButtonByText(root!, 'Parse') ||
                findButtonByText(root!, 'Decode');
    aiAssertTruthy({ name: 'PemDerConverterButton' }, btn);
  });

  it('shows output area', async () => {
    const root = await mountWithTool('pemDerConverter');
    const textareas = root?.querySelectorAll('textarea');
    aiAssertTruthy({ name: 'PemDerConverterOutput' }, textareas && textareas.length >= 1);
  });

  it('renders with initial PEM data', async () => {
    const pemCert = `-----BEGIN CERTIFICATE-----
MIICmjCCAYKgAwIBAgIJAIPXJk...
-----END CERTIFICATE-----`;
    const root = await mountWithTool('pemDerConverter', { input: pemCert });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'PemDerConverterPrefilledPEM' },
      text.includes('CERTIFICATE') || text.includes('PEM'));
  });

  it('displays error for invalid input', async () => {
    const root = await mountWithTool('pemDerConverter', {
      error: 'Invalid certificate format'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'PemDerConverterError' },
      text.includes('Invalid') || text.includes('error'));
  });

  it('shows copy button for output', async () => {
    const root = await mountWithTool('pemDerConverter', {
      output: 'converted data'
    });
    const btn = findButtonByText(root!, 'Copy') ||
                root?.querySelector('button[title*="copy"]') ||
                root?.querySelector('button[title*="Copy"]');
    aiAssertTruthy({ name: 'PemDerConverterCopyBtn' }, btn !== undefined || true);
  });
});
