import React from 'react';
import type { EmailBreachCheckerData, BreachInfo } from './tool-types';

// Format large numbers
const formatCount = (count: number): string => {
  if (count >= 1000000000) {
    return `${(count / 1000000000).toFixed(1)}B`;
  }
  if (count >= 1000000) {
    return `${(count / 1000000).toFixed(1)}M`;
  }
  if (count >= 1000) {
    return `${(count / 1000).toFixed(1)}K`;
  }
  return count.toString();
};

// Validate email format
const isValidEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const EmailBreachCheckerToolComponent = ({
  data,
  onChange,
  onCheck
}: {
  data: EmailBreachCheckerData | undefined;
  onChange: (next: EmailBreachCheckerData) => void;
  onCheck: (email: string) => Promise<void>;
}) => {
  const email = data?.email ?? '';
  const loading = data?.loading ?? false;
  const breaches = data?.breaches ?? [];
  const checkedAt = data?.checkedAt;
  const error = data?.error;

  const handleEmailChange = (value: string) => {
    onChange({ ...data, email: value.trim(), error: undefined });
  };

  const handleCheck = async () => {
    if (!email || !isValidEmail(email) || loading) return;
    await onCheck(email);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && email && isValidEmail(email)) {
      handleCheck();
    }
  };

  const handleClear = () => {
    onChange({});
  };

  const totalExposed = breaches.reduce((sum, b) => sum + b.pwnCount, 0);
  const isEmailValid = email.length > 0 && isValidEmail(email);
  const hasChecked = checkedAt !== undefined;
  const isSafe = hasChecked && breaches.length === 0 && !error;
  const isPwned = hasChecked && breaches.length > 0;

  return (
    <div className="xcalibr-flex xcalibr-flex-col xcalibr-gap-3">
      <div className="xcalibr-flex xcalibr-gap-2">
        <input
          type="email"
          value={email}
          onChange={(e) => handleEmailChange(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Enter email address"
          className="xcalibr-flex-1 xcalibr-bg-[#1e1e1e] xcalibr-border xcalibr-border-[#333] xcalibr-rounded xcalibr-px-2 xcalibr-py-1 xcalibr-text-sm xcalibr-text-white"
          disabled={loading}
        />
        <button
          onClick={handleCheck}
          disabled={!isEmailValid || loading}
          className="xcalibr-bg-blue-600 xcalibr-text-white xcalibr-px-3 xcalibr-py-1 xcalibr-rounded xcalibr-text-sm hover:xcalibr-bg-blue-700 disabled:xcalibr-opacity-50 disabled:xcalibr-cursor-not-allowed"
        >
          {loading ? 'Checking...' : 'Check'}
        </button>
      </div>

      {email && !isEmailValid && (
        <div className="xcalibr-text-xs xcalibr-text-yellow-400">
          Please enter a valid email address
        </div>
      )}

      {error && (
        <div className="xcalibr-bg-red-500/20 xcalibr-border xcalibr-border-red-500/50 xcalibr-rounded xcalibr-p-2 xcalibr-text-sm xcalibr-text-red-400">
          {error}
        </div>
      )}

      {isSafe && (
        <div className="xcalibr-bg-green-500/20 xcalibr-border xcalibr-border-green-500/50 xcalibr-rounded xcalibr-p-3 xcalibr-text-center">
          <div className="xcalibr-text-2xl xcalibr-mb-1">✓</div>
          <div className="xcalibr-text-green-400 xcalibr-font-medium">No breaches found</div>
          <div className="xcalibr-text-xs xcalibr-text-gray-400 xcalibr-mt-1">
            This email was not found in any known data breaches
          </div>
        </div>
      )}

      {isPwned && (
        <div className="xcalibr-flex xcalibr-flex-col xcalibr-gap-3">
          <div className="xcalibr-bg-red-500/20 xcalibr-border xcalibr-border-red-500/50 xcalibr-rounded xcalibr-p-3 xcalibr-text-center">
            <div className="xcalibr-text-2xl xcalibr-mb-1">⚠</div>
            <div className="xcalibr-text-red-400 xcalibr-font-medium">
              Found in {breaches.length} breach{breaches.length > 1 ? 'es' : ''}
            </div>
            <div className="xcalibr-text-xs xcalibr-text-gray-400 xcalibr-mt-1">
              {formatCount(totalExposed)} accounts exposed
            </div>
          </div>

          <div className="xcalibr-flex xcalibr-justify-between xcalibr-items-center">
            <span className="xcalibr-text-sm xcalibr-text-gray-400">
              Breaches ({breaches.length})
            </span>
            <button
              onClick={handleClear}
              className="xcalibr-text-xs xcalibr-text-gray-500 hover:xcalibr-text-gray-300"
            >
              Clear
            </button>
          </div>

          <div className="xcalibr-flex xcalibr-flex-col xcalibr-gap-2 xcalibr-max-h-60 xcalibr-overflow-y-auto">
            {breaches.map((breach) => (
              <BreachCard key={breach.name} breach={breach} />
            ))}
          </div>
        </div>
      )}

      {!hasChecked && !loading && !error && (
        <div className="xcalibr-text-sm xcalibr-text-gray-400 xcalibr-text-center xcalibr-py-4">
          Enter an email to check if it has been compromised in a data breach
        </div>
      )}
    </div>
  );
};

const BreachCard = ({ breach }: { breach: BreachInfo }) => {
  const [expanded, setExpanded] = React.useState(false);

  return (
    <div className="xcalibr-bg-[#1e1e1e] xcalibr-border xcalibr-border-[#333] xcalibr-rounded xcalibr-overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="xcalibr-w-full xcalibr-p-2 xcalibr-text-left xcalibr-flex xcalibr-justify-between xcalibr-items-center hover:xcalibr-bg-[#252525]"
      >
        <div>
          <div className="xcalibr-text-sm xcalibr-text-white xcalibr-font-medium">
            {breach.name}
          </div>
          <div className="xcalibr-text-xs xcalibr-text-gray-500">
            {breach.breachDate} • {formatCount(breach.pwnCount)} accounts
          </div>
        </div>
        <span className="xcalibr-text-gray-500 xcalibr-text-xs">
          {expanded ? '▲' : '▼'}
        </span>
      </button>

      {expanded && (
        <div className="xcalibr-px-2 xcalibr-pb-2 xcalibr-border-t xcalibr-border-[#333]">
          <div className="xcalibr-mt-2 xcalibr-text-xs xcalibr-text-gray-400">
            {breach.description}
          </div>
          <div className="xcalibr-mt-2">
            <div className="xcalibr-text-xs xcalibr-text-gray-500 xcalibr-mb-1">
              Compromised data:
            </div>
            <div className="xcalibr-flex xcalibr-flex-wrap xcalibr-gap-1">
              {breach.dataClasses.map((dc) => (
                <span
                  key={dc}
                  className="xcalibr-bg-[#333] xcalibr-px-1.5 xcalibr-py-0.5 xcalibr-rounded xcalibr-text-xs xcalibr-text-gray-300"
                >
                  {dc}
                </span>
              ))}
            </div>
          </div>
          {breach.isVerified && (
            <div className="xcalibr-mt-2 xcalibr-text-xs xcalibr-text-green-400">
              ✓ Verified breach
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export class EmailBreachCheckerTool {
  static Component = EmailBreachCheckerToolComponent;
}
