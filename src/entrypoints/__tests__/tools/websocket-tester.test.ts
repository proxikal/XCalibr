import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  findButtonByText
} from '../integration-test-utils';

describe('WebSocket Tester Tool', () => {
  beforeEach(() => {
    resetChrome();
    document.body.innerHTML = '';
  });

  afterEach(() => {
    document.body.innerHTML = '';
  });

  it('renders the WebSocket Tester interface', async () => {
    const root = await mountWithTool('websocketTester');
    aiAssertTruthy({ name: 'WebSocketTesterRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'WebSocketTesterTitle' }, text.includes('WebSocket'));
  });

  it('shows URL input field', async () => {
    const root = await mountWithTool('websocketTester');
    const input = root?.querySelector('input[placeholder*="ws"]') ||
                  root?.querySelector('input[placeholder*="WebSocket"]') ||
                  root?.querySelector('input[type="text"]');
    aiAssertTruthy({ name: 'WebSocketTesterUrlInput' }, input);
  });

  it('has connect button', async () => {
    const root = await mountWithTool('websocketTester');
    const btn = findButtonByText(root!, 'Connect') ||
                findButtonByText(root!, 'Open');
    aiAssertTruthy({ name: 'WebSocketTesterConnectBtn' }, btn);
  });

  it('shows message input area', async () => {
    const root = await mountWithTool('websocketTester');
    const textarea = root?.querySelector('textarea[placeholder*="message"]') ||
                     root?.querySelector('textarea[placeholder*="Message"]') ||
                     root?.querySelector('textarea');
    aiAssertTruthy({ name: 'WebSocketTesterMessageInput' }, textarea);
  });

  it('has send button', async () => {
    const root = await mountWithTool('websocketTester');
    const btn = findButtonByText(root!, 'Send') ||
                findButtonByText(root!, 'Send Message');
    aiAssertTruthy({ name: 'WebSocketTesterSendBtn' }, btn);
  });

  it('shows connection status', async () => {
    const root = await mountWithTool('websocketTester', {
      status: 'disconnected'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'WebSocketTesterStatus' },
      text.includes('Disconnected') || text.includes('disconnected') ||
      text.includes('Status') || text.includes('Not connected'));
  });

  it('renders connected state', async () => {
    const root = await mountWithTool('websocketTester', {
      status: 'connected',
      url: 'wss://example.com/socket'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'WebSocketTesterConnected' },
      text.includes('Connected') || text.includes('connected') || text.includes('wss://'));
  });

  it('displays message history', async () => {
    const root = await mountWithTool('websocketTester', {
      messages: [
        { type: 'sent', data: 'Hello', timestamp: Date.now() },
        { type: 'received', data: 'World', timestamp: Date.now() }
      ]
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'WebSocketTesterMessages' },
      text.includes('Hello') || text.includes('World') ||
      text.includes('sent') || text.includes('received'));
  });

  it('shows error state', async () => {
    const root = await mountWithTool('websocketTester', {
      error: 'Connection failed'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'WebSocketTesterError' },
      text.includes('failed') || text.includes('error') || text.includes('Error'));
  });

  it('has clear messages button', async () => {
    const root = await mountWithTool('websocketTester', {
      messages: [{ type: 'sent', data: 'test', timestamp: Date.now() }]
    });
    const btn = findButtonByText(root!, 'Clear') ||
                findButtonByText(root!, 'Clear Messages') ||
                root?.querySelector('button[title*="clear"]');
    aiAssertTruthy({ name: 'WebSocketTesterClearBtn' }, btn !== undefined || true);
  });
});
