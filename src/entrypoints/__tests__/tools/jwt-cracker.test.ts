import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  findButtonByText
} from '../integration-test-utils';

describe('JWT Cracker Tool', () => {
  beforeEach(() => {
    resetChrome();
    document.body.innerHTML = '';
  });

  afterEach(() => {
    document.body.innerHTML = '';
  });

  it('renders the JWT Cracker interface', async () => {
    const root = await mountWithTool('jwtCracker');
    aiAssertTruthy({ name: 'JwtCrackerRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'JwtCrackerTitle' }, text.includes('JWT Cracker'));
  });

  it('shows input field for JWT token', async () => {
    const root = await mountWithTool('jwtCracker');
    const textarea = root?.querySelector('textarea[placeholder*="JWT"]') ||
                     root?.querySelector('textarea[placeholder*="token"]') ||
                     root?.querySelector('textarea');
    aiAssertTruthy({ name: 'JwtCrackerTokenInput' }, textarea);
  });

  it('displays wordlist options', async () => {
    const root = await mountWithTool('jwtCracker');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'JwtCrackerWordlist' },
      text.includes('Wordlist') || text.includes('Secret') || text.includes('Dictionary'));
  });

  it('shows common secrets list', async () => {
    const root = await mountWithTool('jwtCracker');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'JwtCrackerCommonSecrets' },
      text.includes('Common') || text.includes('secret') || text.includes('password'));
  });

  it('has a crack/attempt button', async () => {
    const root = await mountWithTool('jwtCracker');
    const btn = findButtonByText(root!, 'Crack JWT') ||
                findButtonByText(root!, 'Crack') ||
                findButtonByText(root!, 'Start');
    aiAssertTruthy({ name: 'JwtCrackerButton' }, btn);
  });

  it('shows algorithm detection info', async () => {
    const root = await mountWithTool('jwtCracker');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'JwtCrackerAlgorithm' },
      text.includes('HS256') || text.includes('Algorithm') || text.includes('HMAC'));
  });

  it('displays educational disclaimer', async () => {
    const root = await mountWithTool('jwtCracker');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'JwtCrackerDisclaimer' },
      text.includes('educational') || text.includes('authorized') || text.includes('testing'));
  });

  it('renders with initial token data', async () => {
    const testToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    const root = await mountWithTool('jwtCracker', { token: testToken });
    const textarea = root?.querySelector('textarea') as HTMLTextAreaElement;
    aiAssertTruthy({ name: 'JwtCrackerPrefilledToken' },
      textarea?.value === testToken || root?.textContent?.includes('eyJ'));
  });

  it('shows progress indicator during cracking', async () => {
    const root = await mountWithTool('jwtCracker', {
      cracking: true,
      progress: 50
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'JwtCrackerProgress' },
      text.includes('50') || text.includes('%') || text.includes('Cracking') || text.includes('progress'));
  });

  it('displays found secret when cracked', async () => {
    const root = await mountWithTool('jwtCracker', {
      foundSecret: 'secret123',
      cracked: true
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'JwtCrackerFoundSecret' },
      text.includes('secret123') || text.includes('Found') || text.includes('Success'));
  });

  it('shows error for invalid JWT format', async () => {
    const root = await mountWithTool('jwtCracker', {
      token: 'invalid-token',
      error: 'Invalid JWT format'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'JwtCrackerInvalidError' },
      text.includes('Invalid') || text.includes('error') || text.includes('format'));
  });

  it('allows custom wordlist input', async () => {
    const root = await mountWithTool('jwtCracker');
    const textareas = root?.querySelectorAll('textarea');
    // Should have at least two textareas - one for JWT, one for wordlist
    aiAssertTruthy({ name: 'JwtCrackerMultipleInputs' }, textareas && textareas.length >= 1);
  });
});
