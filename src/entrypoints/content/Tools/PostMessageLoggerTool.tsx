import React, { useEffect, useRef, useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faPlay, faStop, faTrash, faCopy, faCheck, faExpand } from '@fortawesome/free-solid-svg-icons';

export type PostMessageEntry = {
  id: string;
  timestamp: number;
  origin: string;
  data: string;
  dataType: string;
  source: string;
};

export type PostMessageLoggerData = {
  isListening?: boolean;
  messages?: PostMessageEntry[];
  filter?: string;
  expandedId?: string | null;
};

type Props = {
  data: PostMessageLoggerData | undefined;
  onChange: (data: PostMessageLoggerData) => void;
};

const PostMessageLogger: React.FC<Props> = ({ data, onChange }) => {
  const isListening = data?.isListening ?? false;
  const messages = data?.messages ?? [];
  const filter = data?.filter ?? '';
  const expandedId = data?.expandedId ?? null;
  const [copied, setCopied] = useState<string | null>(null);
  const listenerRef = useRef<((event: MessageEvent) => void) | null>(null);

  const formatData = (eventData: unknown): { text: string; type: string } => {
    if (eventData === null) return { text: 'null', type: 'null' };
    if (eventData === undefined) return { text: 'undefined', type: 'undefined' };

    const type = typeof eventData;

    if (type === 'object') {
      try {
        return { text: JSON.stringify(eventData, null, 2), type: 'object' };
      } catch {
        return { text: String(eventData), type: 'object' };
      }
    }

    return { text: String(eventData), type };
  };

  const handleMessage = (event: MessageEvent) => {
    const { text, type } = formatData(event.data);

    const entry: PostMessageEntry = {
      id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: Date.now(),
      origin: event.origin || 'unknown',
      data: text,
      dataType: type,
      source: event.source === window ? 'self' : 'external'
    };

    onChange({
      ...data,
      messages: [...(data?.messages ?? []), entry]
    });
  };

  const startListening = () => {
    if (listenerRef.current) return;

    listenerRef.current = handleMessage;
    window.addEventListener('message', listenerRef.current);
    onChange({ ...data, isListening: true });
  };

  const stopListening = () => {
    if (listenerRef.current) {
      window.removeEventListener('message', listenerRef.current);
      listenerRef.current = null;
    }
    onChange({ ...data, isListening: false });
  };

  const clearMessages = () => {
    onChange({ ...data, messages: [], expandedId: null });
  };

  const copyMessage = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(text);
    setTimeout(() => setCopied(null), 2000);
  };

  const toggleExpand = (id: string) => {
    onChange({
      ...data,
      expandedId: expandedId === id ? null : id
    });
  };

  // Cleanup listener on unmount
  useEffect(() => {
    return () => {
      if (listenerRef.current) {
        window.removeEventListener('message', listenerRef.current);
      }
    };
  }, []);

  // Re-attach listener if it was active
  useEffect(() => {
    if (isListening && !listenerRef.current) {
      listenerRef.current = handleMessage;
      window.addEventListener('message', listenerRef.current);
    }
  }, [isListening]);

  const filteredMessages = messages.filter(m => {
    if (!filter.trim()) return true;
    const searchTerm = filter.toLowerCase();
    return (
      m.origin.toLowerCase().includes(searchTerm) ||
      m.data.toLowerCase().includes(searchTerm) ||
      m.dataType.toLowerCase().includes(searchTerm)
    );
  });

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">PostMessage Logger</div>
        <div className="flex gap-2">
          <button
            onClick={clearMessages}
            disabled={messages.length === 0}
            className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors disabled:opacity-50"
            title="Clear all messages"
          >
            <FontAwesomeIcon icon={faTrash} className="w-3 h-3" />
          </button>
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Logs and displays postMessage events sent to this window. Useful for analyzing cross-origin communication.
      </div>

      <div className="flex gap-2 mb-3">
        {!isListening ? (
          <button
            onClick={startListening}
            className="flex-1 rounded bg-green-600/20 border border-green-500/30 px-2 py-1.5 text-[11px] text-green-300 hover:bg-green-600/30 transition-colors flex items-center justify-center gap-2"
          >
            <FontAwesomeIcon icon={faPlay} className="w-3 h-3" />
            Start Listening
          </button>
        ) : (
          <button
            onClick={stopListening}
            className="flex-1 rounded bg-red-600/20 border border-red-500/30 px-2 py-1.5 text-[11px] text-red-300 hover:bg-red-600/30 transition-colors flex items-center justify-center gap-2"
          >
            <FontAwesomeIcon icon={faStop} className="w-3 h-3" />
            Stop Listening
          </button>
        )}
      </div>

      {isListening && (
        <div className="flex items-center gap-2 text-[11px] text-green-400 mb-3">
          <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></span>
          Listening for postMessage events...
        </div>
      )}

      {messages.length > 0 && (
        <>
          <div className="mb-2">
            <input
              type="text"
              value={filter}
              onChange={(e) => onChange({ ...data, filter: e.target.value })}
              placeholder="Filter messages by origin or content..."
              className="w-full rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="text-[10px] text-slate-500 mb-2">
            {filteredMessages.length} of {messages.length} messages
          </div>

          <div className="flex-1 overflow-y-auto space-y-2 min-h-0">
            {filteredMessages.map((m) => (
              <div
                key={m.id}
                className="rounded border border-slate-700 bg-slate-800/50 overflow-hidden"
              >
                <div className="flex items-center justify-between p-2 border-b border-slate-700">
                  <div className="flex items-center gap-2">
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-medium ${
                      m.source === 'self' ? 'bg-blue-600/50' : 'bg-purple-600/50'
                    } text-slate-200`}>
                      {m.source}
                    </span>
                    <span className="text-slate-400 text-[10px]">{m.origin}</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <span className="text-slate-500 text-[9px]">
                      {new Date(m.timestamp).toLocaleTimeString()}
                    </span>
                    <button
                      onClick={() => copyMessage(m.data)}
                      className="text-[9px] text-slate-500 hover:text-slate-300 p-1"
                      title="Copy data"
                    >
                      <FontAwesomeIcon icon={copied === m.data ? faCheck : faCopy} className="w-2.5 h-2.5" />
                    </button>
                    <button
                      onClick={() => toggleExpand(m.id)}
                      className="text-[9px] text-slate-500 hover:text-slate-300 p-1"
                      title="Expand/collapse"
                    >
                      <FontAwesomeIcon icon={faExpand} className="w-2.5 h-2.5" />
                    </button>
                  </div>
                </div>
                <div className="p-2">
                  <div className="text-slate-500 text-[9px] mb-1">Type: {m.dataType}</div>
                  <pre className={`text-slate-300 text-[10px] whitespace-pre-wrap break-all ${
                    expandedId === m.id ? '' : 'max-h-16 overflow-hidden'
                  }`}>
                    {m.data}
                  </pre>
                  {m.data.length > 200 && expandedId !== m.id && (
                    <button
                      onClick={() => toggleExpand(m.id)}
                      className="text-blue-400 hover:text-blue-300 text-[9px] mt-1"
                    >
                      Show more...
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {messages.length === 0 && !isListening && (
        <div className="text-[11px] text-slate-500 text-center py-4">
          No messages captured yet. Click "Start Listening" to begin.
        </div>
      )}

      {messages.length === 0 && isListening && (
        <div className="text-[11px] text-slate-500 text-center py-4">
          Waiting for postMessage events...
        </div>
      )}

      <div className="text-[10px] text-slate-500 border-t border-slate-700 pt-2 mt-3 space-y-1">
        <div><strong>Origin:</strong> The source of the message</div>
        <div><strong>Source:</strong> "self" = same window, "external" = iframe or other window</div>
      </div>
    </div>
  );
};

export class PostMessageLoggerTool {
  static Component = PostMessageLogger;
}
