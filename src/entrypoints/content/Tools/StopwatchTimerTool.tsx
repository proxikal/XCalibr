import React, { useState, useRef, useEffect } from 'react';

export type StopwatchTimerData = {
  mode?: 'stopwatch' | 'timer';
  elapsedMs?: number;
  timerDurationMs?: number;
  isRunning?: boolean;
  laps?: number[];
};

type Props = {
  data: StopwatchTimerData | undefined;
  onChange: (data: StopwatchTimerData) => void;
};

const formatTime = (ms: number): string => {
  const totalSeconds = Math.floor(ms / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  const milliseconds = Math.floor((ms % 1000) / 10);

  if (hours > 0) {
    return `${hours}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}.${milliseconds.toString().padStart(2, '0')}`;
  }
  return `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}.${milliseconds.toString().padStart(2, '0')}`;
};

const StopwatchTimer: React.FC<Props> = ({ data, onChange }) => {
  const mode = data?.mode ?? 'stopwatch';
  const elapsedMs = data?.elapsedMs ?? 0;
  const timerDurationMs = data?.timerDurationMs ?? 5 * 60 * 1000; // 5 min default
  const isRunning = data?.isRunning ?? false;
  const laps = data?.laps ?? [];

  const intervalRef = useRef<number | null>(null);
  const startTimeRef = useRef<number>(0);

  useEffect(() => {
    if (isRunning) {
      startTimeRef.current = Date.now() - elapsedMs;
      intervalRef.current = window.setInterval(() => {
        const newElapsed = Date.now() - startTimeRef.current;
        onChange({ ...data, elapsedMs: newElapsed });
      }, 10);
    } else {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    }

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [isRunning]);

  const handleStartStop = () => {
    onChange({ ...data, isRunning: !isRunning });
  };

  const handleReset = () => {
    onChange({ ...data, elapsedMs: 0, isRunning: false, laps: [] });
  };

  const handleLap = () => {
    if (mode === 'stopwatch' && isRunning) {
      onChange({ ...data, laps: [...laps, elapsedMs] });
    }
  };

  const handleModeChange = (newMode: 'stopwatch' | 'timer') => {
    onChange({ ...data, mode: newMode, elapsedMs: 0, isRunning: false, laps: [] });
  };

  const displayTime = mode === 'timer'
    ? Math.max(0, timerDurationMs - elapsedMs)
    : elapsedMs;

  const isTimerComplete = mode === 'timer' && elapsedMs >= timerDurationMs;

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <button
          onClick={() => handleModeChange('stopwatch')}
          className={`flex-1 py-1.5 rounded text-sm ${
            mode === 'stopwatch' ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300'
          }`}
        >
          Stopwatch
        </button>
        <button
          onClick={() => handleModeChange('timer')}
          className={`flex-1 py-1.5 rounded text-sm ${
            mode === 'timer' ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300'
          }`}
        >
          Timer
        </button>
      </div>

      {mode === 'timer' && !isRunning && elapsedMs === 0 && (
        <div>
          <label className="block text-xs text-gray-400 mb-1">Duration (minutes)</label>
          <input
            type="number"
            value={Math.floor(timerDurationMs / 60000)}
            onChange={(e) => onChange({ ...data, timerDurationMs: (parseInt(e.target.value) || 1) * 60000 })}
            min={1}
            max={120}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          />
        </div>
      )}

      <div className={`text-center py-6 ${isTimerComplete ? 'animate-pulse' : ''}`}>
        <div className={`text-4xl font-mono ${isTimerComplete ? 'text-red-400' : 'text-white'}`}>
          {formatTime(displayTime)}
        </div>
        {isTimerComplete && (
          <div className="text-red-400 text-sm mt-2">Time's up!</div>
        )}
      </div>

      <div className="flex gap-2">
        <button
          onClick={handleStartStop}
          disabled={isTimerComplete}
          className={`flex-1 py-2 rounded text-sm ${
            isRunning
              ? 'bg-yellow-600 hover:bg-yellow-500 text-white'
              : 'bg-green-600 hover:bg-green-500 text-white'
          } disabled:bg-gray-600`}
        >
          {isRunning ? 'Pause' : 'Start'}
        </button>
        {mode === 'stopwatch' && (
          <button
            onClick={handleLap}
            disabled={!isRunning}
            className="flex-1 py-2 bg-purple-600 hover:bg-purple-500 disabled:bg-gray-600 text-white rounded text-sm"
          >
            Lap
          </button>
        )}
        <button
          onClick={handleReset}
          className="flex-1 py-2 bg-red-600 hover:bg-red-500 text-white rounded text-sm"
        >
          Reset
        </button>
      </div>

      {laps.length > 0 && (
        <div className="space-y-1">
          <div className="text-xs text-gray-400">Lap Times</div>
          <div className="max-h-32 overflow-y-auto space-y-1">
            {laps.map((lap, i) => (
              <div key={i} className="flex justify-between text-xs bg-[#1a1a2e] px-2 py-1 rounded">
                <span className="text-gray-400">Lap {i + 1}</span>
                <span className="text-white font-mono">{formatTime(lap)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export class StopwatchTimerTool {
  static Component = StopwatchTimer;
}
