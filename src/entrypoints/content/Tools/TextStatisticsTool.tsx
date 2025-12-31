import React, { useEffect } from 'react';

export type TextStatisticsData = {
  input?: string;
  stats?: {
    characters: number;
    charactersNoSpaces: number;
    words: number;
    sentences: number;
    paragraphs: number;
    lines: number;
    readingTime: string;
    speakingTime: string;
  };
};

type Props = {
  data: TextStatisticsData | undefined;
  onChange: (data: TextStatisticsData) => void;
};

const calculateStats = (text: string) => {
  const characters = text.length;
  const charactersNoSpaces = text.replace(/\s/g, '').length;
  const words = text.trim() ? text.trim().split(/\s+/).length : 0;
  const sentences = text.split(/[.!?]+/).filter(s => s.trim()).length;
  const paragraphs = text.split(/\n\s*\n/).filter(p => p.trim()).length || (text.trim() ? 1 : 0);
  const lines = text.split('\n').length;

  // Average reading speed: 200 words per minute
  const readingMinutes = words / 200;
  const readingTime = readingMinutes < 1
    ? `${Math.ceil(readingMinutes * 60)} sec`
    : `${Math.ceil(readingMinutes)} min`;

  // Average speaking speed: 150 words per minute
  const speakingMinutes = words / 150;
  const speakingTime = speakingMinutes < 1
    ? `${Math.ceil(speakingMinutes * 60)} sec`
    : `${Math.ceil(speakingMinutes)} min`;

  return {
    characters,
    charactersNoSpaces,
    words,
    sentences,
    paragraphs,
    lines,
    readingTime,
    speakingTime
  };
};

const TextStatistics: React.FC<Props> = ({ data, onChange }) => {
  const input = data?.input ?? '';
  const stats = data?.stats;

  useEffect(() => {
    const newStats = calculateStats(input);
    onChange({ ...data, stats: newStats });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [input]);

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">Input Text</label>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value })}
          placeholder="Type or paste text here..."
          rows={8}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm resize-none"
        />
      </div>

      <div className="grid grid-cols-2 gap-2">
        <div className="bg-[#1a1a2e] border border-gray-700 rounded p-3 text-center">
          <div className="text-2xl font-bold text-white">{stats?.characters ?? 0}</div>
          <div className="text-xs text-gray-400">Characters</div>
        </div>
        <div className="bg-[#1a1a2e] border border-gray-700 rounded p-3 text-center">
          <div className="text-2xl font-bold text-white">{stats?.charactersNoSpaces ?? 0}</div>
          <div className="text-xs text-gray-400">No Spaces</div>
        </div>
        <div className="bg-[#1a1a2e] border border-gray-700 rounded p-3 text-center">
          <div className="text-2xl font-bold text-blue-400">{stats?.words ?? 0}</div>
          <div className="text-xs text-gray-400">Words</div>
        </div>
        <div className="bg-[#1a1a2e] border border-gray-700 rounded p-3 text-center">
          <div className="text-2xl font-bold text-white">{stats?.sentences ?? 0}</div>
          <div className="text-xs text-gray-400">Sentences</div>
        </div>
        <div className="bg-[#1a1a2e] border border-gray-700 rounded p-3 text-center">
          <div className="text-2xl font-bold text-white">{stats?.paragraphs ?? 0}</div>
          <div className="text-xs text-gray-400">Paragraphs</div>
        </div>
        <div className="bg-[#1a1a2e] border border-gray-700 rounded p-3 text-center">
          <div className="text-2xl font-bold text-white">{stats?.lines ?? 0}</div>
          <div className="text-xs text-gray-400">Lines</div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2">
        <div className="bg-[#1a1a2e] border border-gray-700 rounded p-2">
          <div className="text-xs text-gray-400">Reading Time</div>
          <div className="text-sm text-green-400">{stats?.readingTime ?? '0 sec'}</div>
        </div>
        <div className="bg-[#1a1a2e] border border-gray-700 rounded p-2">
          <div className="text-xs text-gray-400">Speaking Time</div>
          <div className="text-sm text-green-400">{stats?.speakingTime ?? '0 sec'}</div>
        </div>
      </div>
    </div>
  );
};

export class TextStatisticsTool {
  static Component = TextStatistics;
}
