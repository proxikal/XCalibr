import React, { useState, useMemo } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCopy, faCheck, faArrowRight, faTrash, faPlus, faLock, faExchangeAlt } from '@fortawesome/free-solid-svg-icons';
import type { PayloadEncoderData, EncodingType } from './tool-types';

type Props = {
  data: PayloadEncoderData | undefined;
  onChange: (data: PayloadEncoderData) => void;
};

const ENCODING_INFO: Record<EncodingType, { label: string; description: string; color: string }> = {
  url: { label: 'URL', description: 'URL/percent encoding', color: 'bg-blue-500/20 text-blue-400' },
  'double-url': { label: 'Double URL', description: 'Double percent encoding', color: 'bg-blue-600/20 text-blue-300' },
  unicode: { label: 'Unicode', description: 'Unicode escape sequences', color: 'bg-green-500/20 text-green-400' },
  'html-entity': { label: 'HTML Entity', description: 'HTML numeric entities', color: 'bg-yellow-500/20 text-yellow-400' },
  hex: { label: 'Hex', description: 'Hexadecimal encoding', color: 'bg-purple-500/20 text-purple-400' },
  base64: { label: 'Base64', description: 'Base64 encoding', color: 'bg-orange-500/20 text-orange-400' },
  base32: { label: 'Base32', description: 'Base32 encoding', color: 'bg-orange-600/20 text-orange-300' },
  rot13: { label: 'ROT13', description: 'Caesar cipher (13)', color: 'bg-red-500/20 text-red-400' },
  binary: { label: 'Binary', description: 'Binary representation', color: 'bg-cyan-500/20 text-cyan-400' },
  octal: { label: 'Octal', description: 'Octal encoding', color: 'bg-indigo-500/20 text-indigo-400' },
  'js-escape': { label: 'JS Escape', description: 'JavaScript escape', color: 'bg-pink-500/20 text-pink-400' },
  'js-unicode': { label: 'JS Unicode', description: 'JavaScript \\uXXXX', color: 'bg-pink-600/20 text-pink-300' },
  'css-escape': { label: 'CSS Escape', description: 'CSS escape sequences', color: 'bg-teal-500/20 text-teal-400' },
  'sql-char': { label: 'SQL CHAR()', description: 'SQL CHAR() function', color: 'bg-amber-500/20 text-amber-400' }
};

// Encoding functions
const encoders: Record<EncodingType, (s: string) => string> = {
  url: (s: string) => encodeURIComponent(s),
  'double-url': (s: string) => encodeURIComponent(encodeURIComponent(s)),
  unicode: (s: string) => Array.from(s).map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join(''),
  'html-entity': (s: string) => Array.from(s).map(c => '&#' + c.charCodeAt(0) + ';').join(''),
  hex: (s: string) => Array.from(s).map(c => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')).join(''),
  base64: (s: string) => btoa(s),
  base32: (s: string) => {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const bytes = new TextEncoder().encode(s);
    let bits = '';
    for (const byte of bytes) bits += byte.toString(2).padStart(8, '0');
    while (bits.length % 5 !== 0) bits += '0';
    let result = '';
    for (let i = 0; i < bits.length; i += 5) {
      result += alphabet[parseInt(bits.slice(i, i + 5), 2)];
    }
    while (result.length % 8 !== 0) result += '=';
    return result;
  },
  rot13: (s: string) => s.replace(/[a-zA-Z]/g, c => String.fromCharCode(
    c.charCodeAt(0) + (c.toLowerCase() <= 'm' ? 13 : -13)
  )),
  binary: (s: string) => Array.from(s).map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join(' '),
  octal: (s: string) => Array.from(s).map(c => '\\' + c.charCodeAt(0).toString(8).padStart(3, '0')).join(''),
  'js-escape': (s: string) => s.replace(/[\\"']/g, '\\$&').replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t'),
  'js-unicode': (s: string) => Array.from(s).map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join(''),
  'css-escape': (s: string) => Array.from(s).map(c => '\\' + c.charCodeAt(0).toString(16) + ' ').join(''),
  'sql-char': (s: string) => 'CONCAT(' + Array.from(s).map(c => 'CHAR(' + c.charCodeAt(0) + ')').join(',') + ')'
};

// Decoding functions
const decoders: Record<EncodingType, (s: string) => string> = {
  url: (s: string) => {
    try { return decodeURIComponent(s); } catch { return s; }
  },
  'double-url': (s: string) => {
    try { return decodeURIComponent(decodeURIComponent(s)); } catch { return s; }
  },
  unicode: (s: string) => s.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16))),
  'html-entity': (s: string) => s.replace(/&#(\d+);/g, (_, code) => String.fromCharCode(parseInt(code))),
  hex: (s: string) => s.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16))),
  base64: (s: string) => {
    try { return atob(s.replace(/=+$/, '')); } catch { return s; }
  },
  base32: (s: string) => {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const input = s.replace(/=+$/, '').toUpperCase();
    let bits = '';
    for (const char of input) {
      const idx = alphabet.indexOf(char);
      if (idx === -1) return s;
      bits += idx.toString(2).padStart(5, '0');
    }
    const bytes: number[] = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      bytes.push(parseInt(bits.slice(i, i + 8), 2));
    }
    return new TextDecoder().decode(new Uint8Array(bytes));
  },
  rot13: (s: string) => encoders.rot13(s), // ROT13 is self-inverse
  binary: (s: string) => s.split(' ').map(b => String.fromCharCode(parseInt(b, 2))).join(''),
  octal: (s: string) => s.replace(/\\([0-7]{3})/g, (_, oct) => String.fromCharCode(parseInt(oct, 8))),
  'js-escape': (s: string) => s.replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t').replace(/\\(.)/g, '$1'),
  'js-unicode': (s: string) => s.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16))),
  'css-escape': (s: string) => s.replace(/\\([0-9a-fA-F]+)\s?/g, (_, hex) => String.fromCharCode(parseInt(hex, 16))),
  'sql-char': (s: string) => {
    const match = s.match(/CHAR\((\d+)\)/gi);
    if (!match) return s;
    return match.map(m => String.fromCharCode(parseInt(m.replace(/CHAR\(|\)/gi, '')))).join('');
  }
};

const PayloadEncoder: React.FC<Props> = ({ data, onChange }) => {
  const input = data?.input ?? '';
  const mode = data?.mode ?? 'encode';
  const chainOrder = data?.chainOrder ?? [];
  const [copied, setCopied] = useState<string | null>(null);

  // Calculate output based on chain
  const output = useMemo(() => {
    if (!input) return '';

    let result = input;
    const transforms = mode === 'encode' ? encoders : decoders;

    for (const enc of chainOrder) {
      try {
        result = transforms[enc](result);
      } catch {
        // If encoding fails, keep the previous result
      }
    }

    return result;
  }, [input, mode, chainOrder]);

  const addToChain = (enc: EncodingType) => {
    if (!chainOrder.includes(enc)) {
      onChange({ ...data, chainOrder: [...chainOrder, enc] });
    }
  };

  const removeFromChain = (index: number) => {
    onChange({ ...data, chainOrder: chainOrder.filter((_, i) => i !== index) });
  };

  const moveInChain = (fromIndex: number, toIndex: number) => {
    const newChain = [...chainOrder];
    const [removed] = newChain.splice(fromIndex, 1);
    newChain.splice(toIndex, 0, removed);
    onChange({ ...data, chainOrder: newChain });
  };

  const copyOutput = () => {
    navigator.clipboard.writeText(output);
    setCopied('output');
    setTimeout(() => setCopied(null), 2000);
  };

  const swapMode = () => {
    onChange({
      ...data,
      mode: mode === 'encode' ? 'decode' : 'encode',
      input: output,
      output: input
    });
  };

  // Quick encode buttons - single encoding without chain
  const quickEncode = (enc: EncodingType) => {
    onChange({
      ...data,
      chainOrder: [enc]
    });
  };

  return (
    <div className="flex flex-col h-full text-xs">
      <div className="flex items-center justify-between mb-2">
        <div className="text-slate-200 font-medium">
          <FontAwesomeIcon icon={faLock} className="w-3 h-3 mr-1" />
          Payload Encoder
        </div>
        <button
          onClick={swapMode}
          className={`px-2 py-1 text-[10px] rounded transition-colors flex items-center gap-1 ${
            mode === 'encode' ? 'bg-blue-600 text-white' : 'bg-orange-600 text-white'
          }`}
        >
          <FontAwesomeIcon icon={faExchangeAlt} className="w-2.5 h-2.5" />
          {mode === 'encode' ? 'Encode' : 'Decode'}
        </button>
      </div>

      <div className="text-[10px] text-slate-500 mb-2">
        Chain multiple encodings for WAF bypass. Drag to reorder.
      </div>

      {/* Input */}
      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-2">
        <label className="text-[10px] text-slate-500 mb-1 block">Input Payload</label>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value })}
          placeholder="Enter payload to encode/decode..."
          className="w-full h-20 rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700 font-mono resize-none focus:outline-none focus:border-blue-500"
        />
      </div>

      {/* Encoding chain */}
      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-2">
        <div className="flex items-center justify-between mb-2">
          <label className="text-[10px] text-slate-400">Encoding Chain</label>
          {chainOrder.length > 0 && (
            <button
              onClick={() => onChange({ ...data, chainOrder: [] })}
              className="text-[9px] text-red-400 hover:text-red-300"
            >
              Clear All
            </button>
          )}
        </div>

        {chainOrder.length === 0 ? (
          <div className="text-[10px] text-slate-500 italic py-2 text-center">
            Click encodings below to build a chain
          </div>
        ) : (
          <div className="flex flex-wrap gap-1 mb-2">
            {chainOrder.map((enc, i) => (
              <div
                key={i}
                className={`flex items-center gap-1 px-2 py-1 rounded text-[9px] ${ENCODING_INFO[enc].color} border border-slate-700`}
              >
                <span className="font-medium">{i + 1}.</span>
                <span>{ENCODING_INFO[enc].label}</span>
                {i > 0 && (
                  <button
                    onClick={() => moveInChain(i, i - 1)}
                    className="text-slate-400 hover:text-white"
                    title="Move up"
                  >
                    ←
                  </button>
                )}
                {i < chainOrder.length - 1 && (
                  <button
                    onClick={() => moveInChain(i, i + 1)}
                    className="text-slate-400 hover:text-white"
                    title="Move down"
                  >
                    →
                  </button>
                )}
                <button
                  onClick={() => removeFromChain(i)}
                  className="text-red-400 hover:text-red-300 ml-1"
                >
                  <FontAwesomeIcon icon={faTrash} className="w-2 h-2" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Available encodings */}
      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-2">
        <label className="text-[10px] text-slate-500 mb-2 block">Available Encodings</label>
        <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto">
          {(Object.keys(ENCODING_INFO) as EncodingType[]).map(enc => (
            <button
              key={enc}
              onClick={() => addToChain(enc)}
              className={`px-2 py-1 rounded text-[9px] ${ENCODING_INFO[enc].color} border border-slate-700 hover:opacity-80 transition-opacity flex items-center gap-1`}
              title={ENCODING_INFO[enc].description}
            >
              <FontAwesomeIcon icon={faPlus} className="w-1.5 h-1.5" />
              {ENCODING_INFO[enc].label}
            </button>
          ))}
        </div>
      </div>

      {/* Quick encodings */}
      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-2">
        <label className="text-[10px] text-slate-500 mb-1 block">Quick Single Encoding</label>
        <div className="flex flex-wrap gap-1">
          {['url', 'double-url', 'base64', 'unicode', 'html-entity'].map(enc => (
            <button
              key={enc}
              onClick={() => quickEncode(enc as EncodingType)}
              className="px-2 py-0.5 rounded text-[8px] bg-slate-700 text-slate-300 hover:bg-slate-600"
            >
              {ENCODING_INFO[enc as EncodingType].label}
            </button>
          ))}
        </div>
      </div>

      {/* Output */}
      <div className="flex-1 rounded border border-slate-700 bg-slate-800/30 p-2 flex flex-col min-h-0">
        <div className="flex items-center justify-between mb-1">
          <label className="text-[10px] text-slate-400">
            Output
            {chainOrder.length > 0 && (
              <span className="text-slate-500 ml-1">
                ({chainOrder.map(e => ENCODING_INFO[e].label).join(' → ')})
              </span>
            )}
          </label>
          <button
            onClick={copyOutput}
            disabled={!output}
            className="rounded bg-slate-800 px-2 py-0.5 text-[9px] text-slate-300 hover:bg-slate-700 disabled:opacity-50 flex items-center gap-1"
          >
            <FontAwesomeIcon icon={copied === 'output' ? faCheck : faCopy} className="w-2 h-2" />
            {copied === 'output' ? 'Copied!' : 'Copy'}
          </button>
        </div>
        <pre className="flex-1 text-[10px] text-slate-300 bg-slate-800/50 p-2 rounded font-mono overflow-auto whitespace-pre-wrap break-all">
          {output || <span className="text-slate-500 italic">Output will appear here...</span>}
        </pre>
      </div>
    </div>
  );
};

export class PayloadEncoderTool {
  static Component = PayloadEncoder;
}
