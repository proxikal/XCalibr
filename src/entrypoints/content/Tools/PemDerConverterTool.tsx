import React, { useState, useCallback } from 'react';
import type { PemDerConverterData } from './tool-types';

// Base64 utilities
const base64ToArrayBuffer = (base64: string): ArrayBuffer => {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
};

const arrayBufferToBase64 = (buffer: ArrayBuffer): string => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

const arrayBufferToHex = (buffer: ArrayBuffer): string => {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
};

const hexToArrayBuffer = (hex: string): ArrayBuffer => {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes.buffer;
};

// PEM parsing
const parsePem = (pem: string): { type: string; data: ArrayBuffer } | null => {
  const pemRegex = /-----BEGIN ([^-]+)-----\s*([\s\S]*?)\s*-----END \1-----/;
  const match = pem.match(pemRegex);
  if (!match) return null;

  const type = match[1];
  const base64 = match[2].replace(/\s/g, '');

  try {
    const data = base64ToArrayBuffer(base64);
    return { type, data };
  } catch {
    return null;
  }
};

// Convert to PEM format
const toPem = (data: ArrayBuffer, type: string): string => {
  const base64 = arrayBufferToBase64(data);
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${type}-----\n${lines.join('\n')}\n-----END ${type}-----`;
};

// Very basic ASN.1 DER parsing for certificate display
const parseBasicDerInfo = (data: ArrayBuffer): {
  subject?: string;
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  serialNumber?: string;
} | null => {
  try {
    const bytes = new Uint8Array(data);
    // Very basic validation - check for SEQUENCE tag (0x30)
    if (bytes[0] !== 0x30) return null;

    // For real certificates, we'd need a full ASN.1 parser
    // For now, just extract the hex of the serial number area
    const hex = arrayBufferToHex(data);

    // Try to find readable strings (CN=, O=, etc.)
    // This is a simplified approach
    let textContent = '';
    for (let i = 0; i < bytes.length; i++) {
      if (bytes[i] >= 32 && bytes[i] <= 126) {
        textContent += String.fromCharCode(bytes[i]);
      } else {
        textContent += ' ';
      }
    }

    // Extract common patterns
    const cnMatch = textContent.match(/CN=([^,\s]+)/);
    const oMatch = textContent.match(/O=([^,\s]+)/);

    return {
      subject: cnMatch ? `CN=${cnMatch[1]}` : undefined,
      issuer: oMatch ? `O=${oMatch[1]}` : undefined,
      serialNumber: hex.substring(0, 40) + '...'
    };
  } catch {
    return null;
  }
};

type Props = {
  data: PemDerConverterData | undefined;
  onChange: (next: PemDerConverterData) => void;
};

const PemDerConverterToolComponent = ({ data, onChange }: Props) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const inputFormat = data?.inputFormat ?? 'pem';
  const outputFormat = data?.outputFormat ?? 'der';
  const certInfo = data?.certInfo;
  const error = data?.error ?? '';

  const [copied, setCopied] = useState(false);

  const detectFormat = (text: string): 'pem' | 'der' | null => {
    if (text.includes('-----BEGIN')) return 'pem';
    // Check if it looks like hex (DER as hex string)
    if (/^[0-9a-fA-F\s]+$/.test(text.trim())) return 'der';
    return null;
  };

  const handleConvert = useCallback(() => {
    if (!input.trim()) {
      onChange({ ...data, error: 'Please enter certificate data' });
      return;
    }

    try {
      const detected = detectFormat(input.trim());

      if (detected === 'pem') {
        // PEM to DER
        const parsed = parsePem(input.trim());
        if (!parsed) {
          onChange({ ...data, error: 'Invalid PEM format' });
          return;
        }

        const derHex = arrayBufferToHex(parsed.data);
        const info = parseBasicDerInfo(parsed.data);

        onChange({
          ...data,
          inputFormat: 'pem',
          outputFormat: 'der',
          output: derHex,
          certInfo: info || undefined,
          error: ''
        });
      } else if (detected === 'der') {
        // DER (hex) to PEM
        const cleanHex = input.replace(/\s/g, '');
        if (!/^[0-9a-fA-F]+$/.test(cleanHex)) {
          onChange({ ...data, error: 'Invalid hexadecimal DER data' });
          return;
        }

        const derData = hexToArrayBuffer(cleanHex);
        const pemOutput = toPem(derData, 'CERTIFICATE');
        const info = parseBasicDerInfo(derData);

        onChange({
          ...data,
          inputFormat: 'der',
          outputFormat: 'pem',
          output: pemOutput,
          certInfo: info || undefined,
          error: ''
        });
      } else {
        onChange({ ...data, error: 'Could not detect format. Use PEM (-----BEGIN...) or hex-encoded DER.' });
      }
    } catch (err) {
      onChange({
        ...data,
        error: err instanceof Error ? err.message : 'Conversion failed'
      });
    }
  }, [input, data, onChange]);

  const handleCopy = useCallback(() => {
    if (output) {
      navigator.clipboard.writeText(output);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  }, [output]);

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">PEM/DER Certificate Converter</div>

      <div className="space-y-1">
        <div className="text-[11px] text-slate-400">Input (PEM or hex-encoded DER)</div>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value, error: '' })}
          rows={6}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500 font-mono"
          placeholder="-----BEGIN CERTIFICATE-----
MIIC...
-----END CERTIFICATE-----

or hex-encoded DER:
308201..."
        />
      </div>

      <button
        type="button"
        onClick={handleConvert}
        className="w-full rounded bg-emerald-600 text-white text-xs py-2 hover:bg-emerald-500"
      >
        Convert
      </button>

      {certInfo && (
        <div className="space-y-1 bg-slate-800 rounded p-2">
          <div className="text-[11px] text-emerald-400">Certificate Info</div>
          {certInfo.subject && (
            <div className="text-[10px] text-slate-300">
              <span className="text-slate-500">Subject:</span> {certInfo.subject}
            </div>
          )}
          {certInfo.issuer && (
            <div className="text-[10px] text-slate-300">
              <span className="text-slate-500">Issuer:</span> {certInfo.issuer}
            </div>
          )}
          {certInfo.serialNumber && (
            <div className="text-[10px] text-slate-300">
              <span className="text-slate-500">Serial:</span>{' '}
              <span className="font-mono">{certInfo.serialNumber}</span>
            </div>
          )}
        </div>
      )}

      {output && (
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <div className="text-[11px] text-slate-400">
              Output ({inputFormat === 'pem' ? 'DER (hex)' : 'PEM'})
            </div>
            <button
              type="button"
              onClick={handleCopy}
              className="text-[10px] text-slate-400 hover:text-white"
            >
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <textarea
            value={output}
            readOnly
            rows={6}
            className="w-full rounded bg-slate-900 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none font-mono"
          />
        </div>
      )}

      {error && (
        <div className="bg-red-900/30 border border-red-700 rounded p-2 text-[10px] text-red-300">
          {error}
        </div>
      )}

      <div className="text-[10px] text-slate-500">
        Convert between PEM (Base64 with headers) and DER (binary/hex) certificate formats.
        Paste a PEM certificate or hex-encoded DER data.
      </div>
    </div>
  );
};

export class PemDerConverterTool {
  static Component = PemDerConverterToolComponent;
}
