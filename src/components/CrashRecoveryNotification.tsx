/**
 * Crash Recovery Notification Component
 * Shows a notification when the app recovers from a crash
 */

import React, { useEffect, useState } from 'react';
import { useCrashRecovery } from '@/hooks/useAppStore';

export const CrashRecoveryNotification: React.FC = () => {
  const { hasCrashRecoveryData, crashRecoveryData, clearCrashRecoveryData } = useCrashRecovery();
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    if (hasCrashRecoveryData) {
      setIsVisible(true);
    }
  }, [hasCrashRecoveryData]);

  const handleDismiss = () => {
    setIsVisible(false);
    setTimeout(() => {
      clearCrashRecoveryData();
    }, 300);
  };

  if (!isVisible || !crashRecoveryData) {
    return null;
  }

  const timeSinceCrash = Date.now() - crashRecoveryData.timestamp;
  const minutesAgo = Math.floor(timeSinceCrash / 60000);
  const timeText = minutesAgo < 1 ? 'just now' : `${minutesAgo} minute${minutesAgo > 1 ? 's' : ''} ago`;

  return (
    <div className="fixed top-4 left-1/2 transform -translate-x-1/2 z-50 animate-fade-in">
      <div className="bg-dev-card border border-yellow-500/40 rounded-lg shadow-xl p-4 max-w-sm">
        <div className="flex items-start gap-3">
          {/* Warning Icon */}
          <div className="w-10 h-10 rounded-full bg-yellow-500/10 border border-yellow-500/30 flex items-center justify-center shrink-0">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              fill="none"
              viewBox="0 0 24 24"
              strokeWidth="2"
              stroke="currentColor"
              className="w-5 h-5 text-yellow-500"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"
              />
            </svg>
          </div>

          {/* Content */}
          <div className="flex-1 space-y-2">
            <div>
              <h3 className="text-sm font-semibold text-white">Session Restored</h3>
              <p className="text-xs text-slate-400 mt-1">
                Your previous session ended unexpectedly {timeText}. Your work has been recovered.
              </p>
            </div>

            {/* Restored State Info */}
            <div className="bg-dev-darker border border-slate-700 rounded p-2">
              <p className="text-xs text-slate-500">
                <span className="text-dev-green font-medium">✓ Restored:</span> {crashRecoveryData.activeTab} tab
              </p>
            </div>

            {/* Dismiss Button */}
            <button
              onClick={handleDismiss}
              className="w-full bg-yellow-500/10 hover:bg-yellow-500/20 text-yellow-500 text-xs font-medium py-1.5 px-3 rounded transition-colors border border-yellow-500/30"
            >
              Got it
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
