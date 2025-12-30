import React, { useEffect, useCallback } from 'react';
import type { PasswordStrengthData, PasswordAnalysis, PasswordStrengthScore } from './tool-types';

// Common passwords list (simplified subset of top 100)
const COMMON_PASSWORDS = new Set([
  'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'master',
  '1234567', 'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou',
  'password1', 'sunshine', 'princess', 'welcome', 'shadow', 'superman',
  'michael', 'football', 'password123', 'login', 'admin', 'passw0rd',
  '123456789', '1234567890', '000000', '654321', 'qwerty123', 'password1234'
]);

// Simple dictionary words (common words often used in passwords)
const DICTIONARY_WORDS = new Set([
  'password', 'sunshine', 'princess', 'dragon', 'master', 'monkey', 'shadow',
  'baseball', 'football', 'superman', 'batman', 'welcome', 'hello', 'love',
  'secret', 'summer', 'winter', 'spring', 'autumn', 'flower', 'rainbow'
]);

const calculateEntropy = (password: string): number => {
  if (!password) return 0;
  const charsetSize = getCharsetSize(password);
  return Math.round(password.length * Math.log2(charsetSize));
};

const getCharsetSize = (password: string): number => {
  let size = 0;
  if (/[a-z]/.test(password)) size += 26;
  if (/[A-Z]/.test(password)) size += 26;
  if (/[0-9]/.test(password)) size += 10;
  if (/[^a-zA-Z0-9]/.test(password)) size += 32;
  return size || 1;
};

const estimateCrackTime = (entropy: number): string => {
  // Assuming 10 billion guesses per second (modern GPU)
  const guessesPerSecond = 10_000_000_000;
  const totalGuesses = Math.pow(2, entropy);
  const seconds = totalGuesses / guessesPerSecond / 2; // Average case

  if (seconds < 1) return 'instant';
  if (seconds < 60) return `${Math.round(seconds)} seconds`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
  if (seconds < 2592000) return `${Math.round(seconds / 86400)} days`;
  if (seconds < 31536000) return `${Math.round(seconds / 2592000)} months`;
  if (seconds < 31536000 * 100) return `${Math.round(seconds / 31536000)} years`;
  if (seconds < 31536000 * 1000000) return `${Math.round(seconds / 31536000 / 1000)} thousand years`;
  return 'centuries';
};

const getScore = (password: string, entropy: number): PasswordStrengthScore => {
  if (!password || password.length === 0) return 0;
  if (COMMON_PASSWORDS.has(password.toLowerCase())) return 0;
  if (password.length < 6) return 0;
  if (entropy < 28) return 1;
  if (entropy < 36) return 2;
  if (entropy < 60) return 3;
  return 4;
};

const getLabel = (score: PasswordStrengthScore): PasswordAnalysis['label'] => {
  switch (score) {
    case 0: return 'Very Weak';
    case 1: return 'Weak';
    case 2: return 'Fair';
    case 3: return 'Strong';
    case 4: return 'Very Strong';
  }
};

const getSuggestions = (password: string, analysis: Partial<PasswordAnalysis>): string[] => {
  const suggestions: string[] = [];
  if (!password) return suggestions;

  if (password.length < 8) {
    suggestions.push('Use at least 8 characters');
  }
  if (!analysis.hasUppercase) {
    suggestions.push('Add uppercase letters');
  }
  if (!analysis.hasLowercase) {
    suggestions.push('Add lowercase letters');
  }
  if (!analysis.hasNumbers) {
    suggestions.push('Add numbers');
  }
  if (!analysis.hasSymbols) {
    suggestions.push('Add special characters');
  }
  if (analysis.isCommon) {
    suggestions.push('Avoid common passwords');
  }
  if (analysis.isDictionary && !analysis.isCommon) {
    suggestions.push('Avoid dictionary words');
  }

  return suggestions;
};

const analyzePassword = (password: string): PasswordAnalysis => {
  const length = password.length;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumbers = /[0-9]/.test(password);
  const hasSymbols = /[^a-zA-Z0-9]/.test(password);
  const isCommon = COMMON_PASSWORDS.has(password.toLowerCase());
  const isDictionary = DICTIONARY_WORDS.has(password.toLowerCase());
  const entropy = calculateEntropy(password);
  const score = getScore(password, entropy);
  const label = getLabel(score);
  const crackTime = estimateCrackTime(entropy);

  const partialAnalysis = {
    hasUppercase,
    hasLowercase,
    hasNumbers,
    hasSymbols,
    isCommon,
    isDictionary
  };

  const suggestions = getSuggestions(password, partialAnalysis);

  return {
    score,
    label,
    length,
    entropy,
    crackTime,
    hasUppercase,
    hasLowercase,
    hasNumbers,
    hasSymbols,
    isCommon,
    isDictionary,
    suggestions
  };
};

type Props = {
  data: PasswordStrengthData | undefined;
  onChange: (next: PasswordStrengthData) => void;
};

const PasswordStrengthToolComponent = ({ data, onChange }: Props) => {
  const password = data?.password ?? '';
  const analysis = data?.analysis;
  const showPassword = data?.showPassword ?? false;

  const updateAnalysis = useCallback((pwd: string) => {
    if (!pwd) {
      onChange({ ...data, password: pwd, analysis: undefined });
      return;
    }
    const newAnalysis = analyzePassword(pwd);
    onChange({ ...data, password: pwd, analysis: newAnalysis });
  }, [data, onChange]);

  useEffect(() => {
    if (password && !analysis) {
      updateAnalysis(password);
    }
  }, [password, analysis, updateAnalysis]);

  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const pwd = e.target.value;
    updateAnalysis(pwd);
  };

  const toggleShowPassword = () => {
    onChange({ ...data, showPassword: !showPassword });
  };

  const getScoreColor = (score?: PasswordStrengthScore) => {
    switch (score) {
      case 0: return 'bg-red-500';
      case 1: return 'bg-orange-500';
      case 2: return 'bg-yellow-500';
      case 3: return 'bg-emerald-500';
      case 4: return 'bg-green-500';
      default: return 'bg-slate-700';
    }
  };

  const getScoreWidth = (score?: PasswordStrengthScore) => {
    switch (score) {
      case 0: return 'w-1/5';
      case 1: return 'w-2/5';
      case 2: return 'w-3/5';
      case 3: return 'w-4/5';
      case 4: return 'w-full';
      default: return 'w-0';
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Password Strength</div>

      {/* Password input */}
      <div className="space-y-1">
        <div className="relative">
          <input
            type={showPassword ? 'text' : 'password'}
            value={password}
            onChange={handlePasswordChange}
            className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 pr-16 border border-slate-700 focus:outline-none focus:border-emerald-500 transition-colors font-mono"
            placeholder="Enter password to analyze"
          />
          <button
            type="button"
            onClick={toggleShowPassword}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] text-slate-400 hover:text-white transition-colors"
          >
            {showPassword ? 'Hide' : 'Show'}
          </button>
        </div>
      </div>

      {/* Strength meter */}
      <div className="space-y-1">
        <div className="flex items-center justify-between">
          <div className="text-[11px] text-slate-400">Strength</div>
          {analysis && (
            <div className={`text-[11px] font-medium ${
              analysis.score === 0 ? 'text-red-400' :
              analysis.score === 1 ? 'text-orange-400' :
              analysis.score === 2 ? 'text-yellow-400' :
              analysis.score === 3 ? 'text-emerald-400' :
              'text-green-400'
            }`}>
              {analysis.label}
            </div>
          )}
        </div>
        <div className="h-2 bg-slate-800 rounded overflow-hidden">
          <div
            className={`h-full transition-all duration-300 ${getScoreColor(analysis?.score as PasswordStrengthScore)} ${getScoreWidth(analysis?.score as PasswordStrengthScore)}`}
          />
        </div>
      </div>

      {/* Analysis details */}
      {analysis && password && (
        <>
          {/* Character count and entropy */}
          <div className="grid grid-cols-2 gap-2 text-[11px]">
            <div className="bg-slate-800 rounded p-2">
              <div className="text-slate-400">Length</div>
              <div className="text-slate-200">{analysis.length} characters</div>
            </div>
            <div className="bg-slate-800 rounded p-2">
              <div className="text-slate-400">Entropy</div>
              <div className="text-slate-200">{analysis.entropy} bits</div>
            </div>
          </div>

          {/* Crack time */}
          <div className="bg-slate-800 rounded p-2 text-[11px]">
            <div className="text-slate-400">Estimated crack time</div>
            <div className="text-slate-200">{analysis.crackTime}</div>
          </div>

          {/* Character type analysis */}
          <div className="space-y-1">
            <div className="text-[11px] text-slate-400">Character types</div>
            <div className="grid grid-cols-2 gap-1 text-[10px]">
              <div className="flex items-center gap-1">
                <span className={analysis.hasUppercase ? 'text-emerald-400' : 'text-red-400'}>
                  {analysis.hasUppercase ? '\u2713' : '\u2717'}
                </span>
                <span className="text-slate-300">Uppercase</span>
              </div>
              <div className="flex items-center gap-1">
                <span className={analysis.hasLowercase ? 'text-emerald-400' : 'text-red-400'}>
                  {analysis.hasLowercase ? '\u2713' : '\u2717'}
                </span>
                <span className="text-slate-300">Lowercase</span>
              </div>
              <div className="flex items-center gap-1">
                <span className={analysis.hasNumbers ? 'text-emerald-400' : 'text-red-400'}>
                  {analysis.hasNumbers ? '\u2713' : '\u2717'}
                </span>
                <span className="text-slate-300">Numbers</span>
              </div>
              <div className="flex items-center gap-1">
                <span className={analysis.hasSymbols ? 'text-emerald-400' : 'text-red-400'}>
                  {analysis.hasSymbols ? '\u2713' : '\u2717'}
                </span>
                <span className="text-slate-300">Symbols</span>
              </div>
            </div>
          </div>

          {/* Warnings */}
          {(analysis.isCommon || analysis.isDictionary) && (
            <div className="text-[11px] text-rose-300 bg-rose-900/20 border border-rose-800 rounded px-2 py-1.5">
              {analysis.isCommon && <div>This is a common password - avoid using it!</div>}
              {analysis.isDictionary && !analysis.isCommon && <div>This is a dictionary word - consider adding complexity.</div>}
            </div>
          )}

          {/* Suggestions */}
          {analysis.suggestions && analysis.suggestions.length > 0 && analysis.score !== undefined && analysis.score < 4 && (
            <div className="space-y-1">
              <div className="text-[11px] text-slate-400">Suggestions to improve</div>
              <ul className="text-[10px] text-slate-300 space-y-0.5 list-disc list-inside">
                {analysis.suggestions.map((suggestion, i) => (
                  <li key={i}>{suggestion}</li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}

      {/* Info */}
      <div className="text-[10px] text-slate-500">
        Analyzes password entropy, estimates crack time, and checks against common passwords.
      </div>
    </div>
  );
};

export class PasswordStrengthTool {
  static Component = PasswordStrengthToolComponent;
}
