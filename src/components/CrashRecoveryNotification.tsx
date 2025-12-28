/**
 * Crash Recovery Notification Component
 * Shows a notification when the app recovers from a crash
 * Auto-dismisses after 5 seconds
 */

import React, { useEffect, useState } from 'react';
import { useCrashRecovery } from '@/hooks/useAppStore';

export const CrashRecoveryNotification: React.FC = () => {
  const { hasCrashRecoveryData, crashRecoveryData, clearCrashRecoveryData } = useCrashRecovery();
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    if (hasCrashRecoveryData) {
      setIsVisible(true);

      // Auto-dismiss after 5 seconds
      const timer = setTimeout(() => {
        setIsVisible(false);
        setTimeout(() => {
          clearCrashRecoveryData();
        }, 300);
      }, 5000);

      return () => clearTimeout(timer);
    }
  }, [hasCrashRecoveryData, clearCrashRecoveryData]);

  if (!isVisible || !crashRecoveryData) {
    return null;
  }

  const timeSinceCrash = Date.now() - crashRecoveryData.timestamp;
  const minutesAgo = Math.floor(timeSinceCrash / 60000);
  const timeText = minutesAgo < 1 ? 'just now' : `${minutesAgo} minute${minutesAgo > 1 ? 's' : ''} ago`;

  return (
    <div className="fixed bottom-14 left-0 right-0 z-40 px-4 animate-fade-in">
      <div className="w-full bg-dev-card border-t border-yellow-500/40 shadow-xl py-3 px-4">
        <div className="flex items-center gap-3">
          {/* Warning Icon */}
          <div className="w-8 h-8 rounded-full bg-yellow-500/10 border border-yellow-500/30 flex items-center justify-center shrink-0">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              fill="none"
              viewBox="0 0 24 24"
              strokeWidth="2"
              stroke="currentColor"
              className="w-4 h-4 text-yellow-500"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"
              />
            </svg>
          </div>

          {/* Content */}
          <div className="flex-1">
            <p className="text-xs text-slate-300">
              <span className="font-semibold text-white">Session Restored</span> —
              Your previous session ended unexpectedly {timeText}.
              <span className="text-dev-green ml-1">✓ {crashRecoveryData.activeTab} tab restored</span>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
