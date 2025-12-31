import React, { useState } from 'react';
import type { PasswordGeneratorData } from './tool-types';

const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const NUMBERS = '0123456789';
const SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?';

const generateSecurePassword = (
  length: number,
  options: {
    uppercase: boolean;
    lowercase: boolean;
    numbers: boolean;
    symbols: boolean;
  }
): string => {
  let charset = '';
  const required: string[] = [];

  if (options.lowercase) {
    charset += LOWERCASE;
    required.push(LOWERCASE);
  }
  if (options.uppercase) {
    charset += UPPERCASE;
    required.push(UPPERCASE);
  }
  if (options.numbers) {
    charset += NUMBERS;
    required.push(NUMBERS);
  }
  if (options.symbols) {
    charset += SYMBOLS;
    required.push(SYMBOLS);
  }

  if (!charset) {
    throw new Error('At least one character set must be selected');
  }

  // Generate random bytes using crypto API
  const randomValues = new Uint32Array(length);
  crypto.getRandomValues(randomValues);

  // Build password ensuring at least one character from each required set
  const password: string[] = [];

  // First, add one character from each required set
  for (const set of required) {
    const randomIndex = randomValues[password.length] % set.length;
    password.push(set[randomIndex]);
  }

  // Fill the rest with random characters from the full charset
  while (password.length < length) {
    const randomIndex = randomValues[password.length] % charset.length;
    password.push(charset[randomIndex]);
  }

  // Shuffle the password using Fisher-Yates algorithm with crypto random
  const shuffleValues = new Uint32Array(password.length);
  crypto.getRandomValues(shuffleValues);
  for (let i = password.length - 1; i > 0; i--) {
    const j = shuffleValues[i] % (i + 1);
    [password[i], password[j]] = [password[j], password[i]];
  }

  return password.join('');
};

const calculateEntropy = (
  length: number,
  options: { uppercase: boolean; lowercase: boolean; numbers: boolean; symbols: boolean }
): number => {
  let charsetSize = 0;
  if (options.lowercase) charsetSize += 26;
  if (options.uppercase) charsetSize += 26;
  if (options.numbers) charsetSize += 10;
  if (options.symbols) charsetSize += 26; // Simplified symbols count
  if (charsetSize === 0) return 0;
  return Math.round(length * Math.log2(charsetSize));
};

type Props = {
  data: PasswordGeneratorData | undefined;
  onChange: (next: PasswordGeneratorData) => void;
};

const PasswordGeneratorToolComponent = ({ data, onChange }: Props) => {
  const password = data?.password ?? '';
  const length = data?.length ?? 16;
  const uppercase = data?.uppercase ?? true;
  const lowercase = data?.lowercase ?? true;
  const numbers = data?.numbers ?? true;
  const symbols = data?.symbols ?? true;
  const history = data?.history ?? [];
  const error = data?.error;
  const [copied, setCopied] = useState(false);

  const handleGenerate = () => {
    try {
      const newPassword = generateSecurePassword(length, {
        uppercase,
        lowercase,
        numbers,
        symbols
      });
      const newHistory = [password, ...history].filter(Boolean).slice(0, 5);
      onChange({
        ...data,
        password: newPassword,
        history: newHistory,
        error: undefined
      });
    } catch (err) {
      onChange({
        ...data,
        error: err instanceof Error ? err.message : 'Failed to generate password'
      });
    }
  };

  const handleCopy = () => {
    if (password) {
      navigator.clipboard.writeText(password);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  };

  const entropy = calculateEntropy(length, { uppercase, lowercase, numbers, symbols });

  const getStrengthLabel = (bits: number): string => {
    if (bits < 28) return 'Very Weak';
    if (bits < 36) return 'Weak';
    if (bits < 60) return 'Fair';
    if (bits < 80) return 'Strong';
    return 'Very Strong';
  };

  const getStrengthColor = (bits: number): string => {
    if (bits < 28) return 'text-red-400';
    if (bits < 36) return 'text-orange-400';
    if (bits < 60) return 'text-yellow-400';
    if (bits < 80) return 'text-emerald-400';
    return 'text-green-400';
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Password Generator</div>

      {/* Length slider */}
      <div className="space-y-1">
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-slate-400">Length</span>
          <span className="text-slate-200 font-mono">{length}</span>
        </div>
        <input
          type="range"
          min="4"
          max="128"
          value={length}
          onChange={(e) => onChange({ ...data, length: parseInt(e.target.value, 10) })}
          className="w-full h-2 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-emerald-500"
        />
        <div className="flex justify-between text-[10px] text-slate-500">
          <span>4</span>
          <span>128</span>
        </div>
      </div>

      {/* Character set checkboxes */}
      <div className="space-y-1">
        <div className="text-[11px] text-slate-400">Character Sets</div>
        <div className="grid grid-cols-2 gap-2">
          <label className="flex items-center gap-2 text-[11px] text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={uppercase}
              onChange={(e) => onChange({ ...data, uppercase: e.target.checked })}
              className="rounded border-slate-600 bg-slate-800 text-emerald-500 focus:ring-emerald-500 focus:ring-offset-slate-900"
            />
            Uppercase (A-Z)
          </label>
          <label className="flex items-center gap-2 text-[11px] text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={lowercase}
              onChange={(e) => onChange({ ...data, lowercase: e.target.checked })}
              className="rounded border-slate-600 bg-slate-800 text-emerald-500 focus:ring-emerald-500 focus:ring-offset-slate-900"
            />
            Lowercase (a-z)
          </label>
          <label className="flex items-center gap-2 text-[11px] text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={numbers}
              onChange={(e) => onChange({ ...data, numbers: e.target.checked })}
              className="rounded border-slate-600 bg-slate-800 text-emerald-500 focus:ring-emerald-500 focus:ring-offset-slate-900"
            />
            Numbers (0-9)
          </label>
          <label className="flex items-center gap-2 text-[11px] text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={symbols}
              onChange={(e) => onChange({ ...data, symbols: e.target.checked })}
              className="rounded border-slate-600 bg-slate-800 text-emerald-500 focus:ring-emerald-500 focus:ring-offset-slate-900"
            />
            Symbols (!@#$...)
          </label>
        </div>
      </div>

      {/* Entropy display */}
      <div className="bg-slate-800 rounded p-2 text-[11px]">
        <div className="flex items-center justify-between">
          <span className="text-slate-400">Entropy</span>
          <span className={getStrengthColor(entropy)}>{entropy} bits - {getStrengthLabel(entropy)}</span>
        </div>
      </div>

      {/* Generate button */}
      <button
        type="button"
        onClick={handleGenerate}
        className="w-full rounded bg-emerald-600 px-2 py-1.5 text-xs text-white hover:bg-emerald-500 transition-colors"
      >
        Generate
      </button>

      {/* Error display */}
      {error && (
        <div className="text-[11px] text-rose-300 bg-rose-900/20 border border-rose-800 rounded px-2 py-1.5">
          {error}
        </div>
      )}

      {/* Password output */}
      {password && (
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <div className="text-[11px] text-slate-400">Generated Password</div>
            <button
              type="button"
              onClick={handleCopy}
              className="text-[10px] text-slate-400 hover:text-white transition-colors"
            >
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <div
            className="bg-slate-900 border border-slate-700 rounded p-2 text-[11px] text-slate-200 font-mono break-all select-all cursor-text"
            onClick={handleCopy}
          >
            {password}
          </div>
        </div>
      )}

      {/* History */}
      {history.length > 0 && (
        <div className="space-y-1">
          <div className="text-[11px] text-slate-400">Recent Passwords</div>
          <div className="space-y-1 max-h-24 overflow-y-auto">
            {history.map((pwd, i) => (
              <div
                key={i}
                className="bg-slate-800 rounded px-2 py-1 text-[10px] text-slate-400 font-mono truncate cursor-pointer hover:text-slate-200"
                onClick={() => {
                  navigator.clipboard.writeText(pwd);
                }}
                title="Click to copy"
              >
                {pwd}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Info */}
      <div className="text-[10px] text-slate-500">
        Uses cryptographically secure random number generation (crypto.getRandomValues).
      </div>
    </div>
  );
};

export class PasswordGeneratorTool {
  static Component = PasswordGeneratorToolComponent;
}
