import React, { useState, useRef, useCallback, useEffect } from 'react';
import type { WebSocketTesterData, WebSocketMessage } from './tool-types';

const formatTimestamp = (ts: number): string => {
  const date = new Date(ts);
  return date.toLocaleTimeString();
};

type Props = {
  data: WebSocketTesterData | undefined;
  onChange: (next: WebSocketTesterData) => void;
};

const WebSocketTesterToolComponent = ({ data, onChange }: Props) => {
  const url = data?.url ?? 'wss://';
  const status = data?.status ?? 'disconnected';
  const message = data?.message ?? '';
  const messages = data?.messages ?? [];
  const error = data?.error ?? '';

  const wsRef = useRef<WebSocket | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  useEffect(() => {
    if (autoScroll && messagesEndRef.current?.scrollIntoView) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, autoScroll]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const addMessage = useCallback(
    (msg: WebSocketMessage) => {
      onChange({
        ...data,
        messages: [...(data?.messages ?? []), msg]
      });
    },
    [data, onChange]
  );

  const handleConnect = useCallback(() => {
    if (!url.trim()) {
      onChange({ ...data, error: 'Please enter a WebSocket URL' });
      return;
    }

    if (!url.startsWith('ws://') && !url.startsWith('wss://')) {
      onChange({ ...data, error: 'URL must start with ws:// or wss://' });
      return;
    }

    if (wsRef.current) {
      wsRef.current.close();
    }

    onChange({ ...data, status: 'connecting', error: '' });

    try {
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        onChange({
          ...data,
          status: 'connected',
          error: '',
          messages: [
            ...(data?.messages ?? []),
            { type: 'received', data: '[Connected]', timestamp: Date.now() }
          ]
        });
      };

      ws.onmessage = (event) => {
        const messageData = typeof event.data === 'string' ? event.data : '[Binary data]';
        addMessage({ type: 'received', data: messageData, timestamp: Date.now() });
      };

      ws.onerror = () => {
        onChange({
          ...data,
          status: 'error',
          error: 'WebSocket error occurred'
        });
      };

      ws.onclose = (event) => {
        onChange({
          ...data,
          status: 'disconnected',
          messages: [
            ...(data?.messages ?? []),
            {
              type: 'received',
              data: `[Disconnected: ${event.code} ${event.reason || 'Connection closed'}]`,
              timestamp: Date.now()
            }
          ]
        });
        wsRef.current = null;
      };
    } catch (err) {
      onChange({
        ...data,
        status: 'error',
        error: err instanceof Error ? err.message : 'Failed to connect'
      });
    }
  }, [url, data, onChange, addMessage]);

  const handleDisconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    onChange({ ...data, status: 'disconnected' });
  }, [data, onChange]);

  const handleSend = useCallback(() => {
    if (!message.trim()) return;
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
      onChange({ ...data, error: 'Not connected to WebSocket' });
      return;
    }

    try {
      wsRef.current.send(message);
      addMessage({ type: 'sent', data: message, timestamp: Date.now() });
      onChange({ ...data, message: '' });
    } catch (err) {
      onChange({
        ...data,
        error: err instanceof Error ? err.message : 'Failed to send message'
      });
    }
  }, [message, data, onChange, addMessage]);

  const handleClear = useCallback(() => {
    onChange({ ...data, messages: [] });
  }, [data, onChange]);

  const getStatusColor = () => {
    switch (status) {
      case 'connected':
        return 'bg-emerald-500';
      case 'connecting':
        return 'bg-yellow-500';
      case 'error':
        return 'bg-red-500';
      default:
        return 'bg-slate-500';
    }
  };

  const getStatusText = () => {
    switch (status) {
      case 'connected':
        return 'Connected';
      case 'connecting':
        return 'Connecting...';
      case 'error':
        return 'Error';
      default:
        return 'Disconnected';
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">WebSocket Tester</div>

      <div className="space-y-1">
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${getStatusColor()}`} />
          <span className="text-[10px] text-slate-400">{getStatusText()}</span>
        </div>

        <div className="flex gap-2">
          <input
            type="text"
            value={url}
            onChange={(e) => onChange({ ...data, url: e.target.value, error: '' })}
            className="flex-1 rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500 font-mono"
            placeholder="wss://example.com/socket"
            disabled={status === 'connected' || status === 'connecting'}
          />
          {status === 'connected' ? (
            <button
              type="button"
              onClick={handleDisconnect}
              className="rounded bg-red-600 text-white text-xs px-3 py-2 hover:bg-red-500"
            >
              Disconnect
            </button>
          ) : (
            <button
              type="button"
              onClick={handleConnect}
              disabled={status === 'connecting'}
              className="rounded bg-emerald-600 text-white text-xs px-3 py-2 hover:bg-emerald-500 disabled:opacity-50"
            >
              Connect
            </button>
          )}
        </div>
      </div>

      <div className="space-y-1">
        <div className="flex items-center justify-between">
          <div className="text-[11px] text-slate-400">Messages</div>
          <div className="flex items-center gap-2">
            <label className="flex items-center gap-1 text-[10px] text-slate-400">
              <input
                type="checkbox"
                checked={autoScroll}
                onChange={(e) => setAutoScroll(e.target.checked)}
                className="w-3 h-3"
              />
              Auto-scroll
            </label>
            <button
              type="button"
              onClick={handleClear}
              className="text-[10px] text-slate-400 hover:text-white"
            >
              Clear
            </button>
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-700 rounded h-40 overflow-y-auto p-2 font-mono text-[10px]">
          {messages.length === 0 ? (
            <div className="text-slate-500 text-center py-4">No messages yet</div>
          ) : (
            messages.map((msg, i) => (
              <div
                key={i}
                className={`py-1 ${msg.type === 'sent' ? 'text-emerald-400' : 'text-slate-300'}`}
              >
                <span className="text-slate-500">[{formatTimestamp(msg.timestamp)}]</span>{' '}
                <span className={msg.type === 'sent' ? 'text-emerald-400' : 'text-cyan-400'}>
                  {msg.type === 'sent' ? '→' : '←'}
                </span>{' '}
                <span className="break-all">{msg.data}</span>
              </div>
            ))
          )}
          <div ref={messagesEndRef} />
        </div>
      </div>

      <div className="space-y-1">
        <div className="text-[11px] text-slate-400">Send Message</div>
        <textarea
          value={message}
          onChange={(e) => onChange({ ...data, message: e.target.value })}
          rows={2}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500 font-mono"
          placeholder="Enter message to send..."
          disabled={status !== 'connected'}
        />
      </div>

      <button
        type="button"
        onClick={handleSend}
        disabled={status !== 'connected' || !message.trim()}
        className="w-full rounded bg-emerald-600 text-white text-xs py-2 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        Send
      </button>

      {error && (
        <div className="bg-red-900/30 border border-red-700 rounded p-2 text-[10px] text-red-300">
          {error}
        </div>
      )}

      <div className="text-[10px] text-slate-500">
        Test WebSocket connections. Send and receive messages in real-time.
        Use wss:// for secure connections or ws:// for unsecured.
      </div>
    </div>
  );
};

export class WebSocketTesterTool {
  static Component = WebSocketTesterToolComponent;
}
