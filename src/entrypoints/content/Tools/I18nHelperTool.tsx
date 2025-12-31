import React from 'react';

type I18nMessage = {
  key: string;
  message: string;
  description?: string;
  placeholders?: Record<string, { content: string; example?: string }>;
};

export type I18nHelperData = {
  newKey?: string;
  newMessage?: string;
  newDescription?: string;
  messages?: I18nMessage[];
  locale?: string;
};

type Props = {
  data: I18nHelperData | undefined;
  onChange: (data: I18nHelperData) => void;
};

const I18nHelper: React.FC<Props> = ({ data, onChange }) => {
  const newKey = data?.newKey ?? '';
  const newMessage = data?.newMessage ?? '';
  const newDescription = data?.newDescription ?? '';
  const messages = data?.messages ?? [];
  const locale = data?.locale ?? 'en';

  const addMessage = () => {
    if (!newKey.trim() || !newMessage.trim()) return;

    const newEntry: I18nMessage = {
      key: newKey.trim(),
      message: newMessage.trim()
    };
    if (newDescription.trim()) {
      newEntry.description = newDescription.trim();
    }

    onChange({
      ...data,
      messages: [...messages, newEntry],
      newKey: '',
      newMessage: '',
      newDescription: ''
    });
  };

  const removeMessage = (key: string) => {
    onChange({
      ...data,
      messages: messages.filter(m => m.key !== key)
    });
  };

  const exportJson = () => {
    const messagesObj: Record<string, { message: string; description?: string }> = {};
    for (const msg of messages) {
      messagesObj[msg.key] = { message: msg.message };
      if (msg.description) {
        messagesObj[msg.key].description = msg.description;
      }
    }

    const json = JSON.stringify(messagesObj, null, 2);
    navigator.clipboard.writeText(json);
  };

  const loadFromJson = () => {
    const input = prompt('Paste messages.json content:');
    if (!input) return;

    try {
      const parsed = JSON.parse(input);
      const loadedMessages: I18nMessage[] = [];
      for (const [key, value] of Object.entries(parsed)) {
        const v = value as { message: string; description?: string };
        loadedMessages.push({
          key,
          message: v.message,
          description: v.description
        });
      }
      onChange({ ...data, messages: loadedMessages });
    } catch {
      alert('Invalid JSON format');
    }
  };

  const downloadJson = () => {
    const messagesObj: Record<string, { message: string; description?: string }> = {};
    for (const msg of messages) {
      messagesObj[msg.key] = { message: msg.message };
      if (msg.description) {
        messagesObj[msg.key].description = msg.description;
      }
    }

    const json = JSON.stringify(messagesObj, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'messages.json';
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2">
        <input
          type="text"
          value={locale}
          onChange={(e) => onChange({ ...data, locale: e.target.value })}
          placeholder="Locale (e.g., en)"
          className="px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
        />
        <div className="flex gap-1">
          <button
            onClick={loadFromJson}
            className="flex-1 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded text-xs"
          >
            Import
          </button>
          <button
            onClick={downloadJson}
            className="flex-1 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded text-xs"
          >
            Download
          </button>
        </div>
      </div>

      <div className="space-y-2">
        <input
          type="text"
          value={newKey}
          onChange={(e) => onChange({ ...data, newKey: e.target.value })}
          placeholder="Message key (e.g., app_name)"
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm font-mono"
        />
        <input
          type="text"
          value={newMessage}
          onChange={(e) => onChange({ ...data, newMessage: e.target.value })}
          placeholder="Message text"
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
        />
        <input
          type="text"
          value={newDescription}
          onChange={(e) => onChange({ ...data, newDescription: e.target.value })}
          placeholder="Description (optional)"
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-gray-300 text-sm"
        />
        <button
          onClick={addMessage}
          disabled={!newKey.trim() || !newMessage.trim()}
          className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 disabled:opacity-50 text-white rounded text-sm"
        >
          Add Message
        </button>
      </div>

      <div>
        <div className="flex justify-between items-center mb-2">
          <label className="text-xs text-gray-400">Messages ({messages.length})</label>
          {messages.length > 0 && (
            <button
              onClick={exportJson}
              className="text-xs text-blue-400 hover:text-blue-300"
            >
              Copy JSON
            </button>
          )}
        </div>
        <div className="max-h-48 overflow-y-auto space-y-1">
          {messages.map((msg) => (
            <div
              key={msg.key}
              className="bg-[#1a1a2e] border border-gray-700 rounded p-2 text-xs"
            >
              <div className="flex justify-between items-start">
                <code className="text-blue-400">{msg.key}</code>
                <button
                  onClick={() => removeMessage(msg.key)}
                  className="text-gray-500 hover:text-red-400"
                >
                  ×
                </button>
              </div>
              <div className="text-white mt-1">{msg.message}</div>
              {msg.description && (
                <div className="text-gray-500 mt-1 italic">{msg.description}</div>
              )}
            </div>
          ))}
          {messages.length === 0 && (
            <div className="text-gray-500 text-center text-xs py-4">
              No messages added yet
            </div>
          )}
        </div>
      </div>

      <div className="text-xs text-gray-500">
        <p>File path: _locales/{locale}/messages.json</p>
      </div>
    </div>
  );
};

export class I18nHelperTool {
  static Component = I18nHelper;
}
