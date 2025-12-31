import React from 'react';

export type LoremIpsumGeneratorData = {
  count?: number;
  type?: 'paragraphs' | 'sentences' | 'words';
  output?: string;
};

type Props = {
  data: LoremIpsumGeneratorData;
  onChange: (data: LoremIpsumGeneratorData) => void;
};

const loremWords = [
  'lorem', 'ipsum', 'dolor', 'sit', 'amet', 'consectetur', 'adipiscing', 'elit',
  'sed', 'do', 'eiusmod', 'tempor', 'incididunt', 'ut', 'labore', 'et', 'dolore',
  'magna', 'aliqua', 'enim', 'ad', 'minim', 'veniam', 'quis', 'nostrud',
  'exercitation', 'ullamco', 'laboris', 'nisi', 'aliquip', 'ex', 'ea', 'commodo',
  'consequat', 'duis', 'aute', 'irure', 'in', 'reprehenderit', 'voluptate',
  'velit', 'esse', 'cillum', 'fugiat', 'nulla', 'pariatur', 'excepteur', 'sint',
  'occaecat', 'cupidatat', 'non', 'proident', 'sunt', 'culpa', 'qui', 'officia',
  'deserunt', 'mollit', 'anim', 'id', 'est', 'laborum', 'perspiciatis', 'unde',
  'omnis', 'iste', 'natus', 'error', 'voluptatem', 'accusantium', 'doloremque',
  'laudantium', 'totam', 'rem', 'aperiam', 'eaque', 'ipsa', 'quae', 'ab', 'illo',
  'inventore', 'veritatis', 'quasi', 'architecto', 'beatae', 'vitae', 'dicta',
  'explicabo', 'nemo', 'ipsam', 'quia', 'voluptas', 'aspernatur', 'aut', 'odit',
  'fugit', 'consequuntur', 'magni', 'dolores', 'eos', 'ratione', 'sequi', 'nesciunt'
];

const generateWords = (count: number): string => {
  const words: string[] = [];
  for (let i = 0; i < count; i++) {
    words.push(loremWords[Math.floor(Math.random() * loremWords.length)]);
  }
  // Capitalize first word
  if (words.length > 0) {
    words[0] = words[0].charAt(0).toUpperCase() + words[0].slice(1);
  }
  return words.join(' ');
};

const generateSentence = (): string => {
  const wordCount = Math.floor(Math.random() * 10) + 5;
  return generateWords(wordCount) + '.';
};

const generateParagraph = (): string => {
  const sentenceCount = Math.floor(Math.random() * 4) + 3;
  const sentences: string[] = [];
  for (let i = 0; i < sentenceCount; i++) {
    sentences.push(generateSentence());
  }
  return sentences.join(' ');
};

const generateLorem = (count: number, type: 'paragraphs' | 'sentences' | 'words'): string => {
  switch (type) {
    case 'words':
      return generateWords(count);
    case 'sentences':
      const sentences: string[] = [];
      for (let i = 0; i < count; i++) {
        sentences.push(generateSentence());
      }
      return sentences.join(' ');
    case 'paragraphs':
    default:
      const paragraphs: string[] = [];
      // First paragraph always starts with "Lorem ipsum dolor sit amet..."
      paragraphs.push('Lorem ipsum dolor sit amet, consectetur adipiscing elit. ' + generateParagraph());
      for (let i = 1; i < count; i++) {
        paragraphs.push(generateParagraph());
      }
      return paragraphs.join('\n\n');
  }
};

const LoremIpsumGenerator: React.FC<Props> = ({ data, onChange }) => {
  const count = data.count ?? 3;
  const type = data.type ?? 'paragraphs';
  const output = data.output ?? '';

  const handleGenerate = () => {
    const text = generateLorem(count, type);
    onChange({ ...data, output: text });
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(output);
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Count</label>
          <input
            type="number"
            min="1"
            max="50"
            value={count}
            onChange={(e) => onChange({ ...data, count: Math.max(1, Number(e.target.value)) })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white"
          />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Type</label>
          <select
            value={type}
            onChange={(e) => onChange({ ...data, type: e.target.value as typeof type })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white"
          >
            <option value="paragraphs">Paragraphs</option>
            <option value="sentences">Sentences</option>
            <option value="words">Words</option>
          </select>
        </div>
      </div>

      <button
        onClick={handleGenerate}
        className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded text-sm"
      >
        Generate Lorem Ipsum
      </button>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Output</label>
        <textarea
          readOnly
          value={output}
          placeholder="Generated text will appear here..."
          className="w-full h-40 px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm resize-none"
        />
      </div>

      <button
        onClick={copyToClipboard}
        disabled={!output}
        className={`w-full py-2 rounded text-sm ${
          output
            ? 'bg-gray-700 hover:bg-gray-600 text-white'
            : 'bg-gray-800 text-gray-500 cursor-not-allowed'
        }`}
      >
        Copy Text
      </button>
    </div>
  );
};

export class LoremIpsumGeneratorTool {
  static Component = LoremIpsumGenerator;
}
