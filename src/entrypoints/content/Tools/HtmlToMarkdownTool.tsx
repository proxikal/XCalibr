import React from 'react';

export type HtmlToMarkdownData = {
  input?: string;
  output?: string;
};

type Props = {
  data: HtmlToMarkdownData;
  onChange: (data: HtmlToMarkdownData) => void;
};

const convertHtmlToMarkdown = (html: string): string => {
  let md = html;

  // Headers
  md = md.replace(/<h1[^>]*>(.*?)<\/h1>/gi, '# $1\n');
  md = md.replace(/<h2[^>]*>(.*?)<\/h2>/gi, '## $1\n');
  md = md.replace(/<h3[^>]*>(.*?)<\/h3>/gi, '### $1\n');
  md = md.replace(/<h4[^>]*>(.*?)<\/h4>/gi, '#### $1\n');
  md = md.replace(/<h5[^>]*>(.*?)<\/h5>/gi, '##### $1\n');
  md = md.replace(/<h6[^>]*>(.*?)<\/h6>/gi, '###### $1\n');

  // Bold
  md = md.replace(/<strong[^>]*>(.*?)<\/strong>/gi, '**$1**');
  md = md.replace(/<b[^>]*>(.*?)<\/b>/gi, '**$1**');

  // Italic
  md = md.replace(/<em[^>]*>(.*?)<\/em>/gi, '*$1*');
  md = md.replace(/<i[^>]*>(.*?)<\/i>/gi, '*$1*');

  // Strikethrough
  md = md.replace(/<del[^>]*>(.*?)<\/del>/gi, '~~$1~~');
  md = md.replace(/<s[^>]*>(.*?)<\/s>/gi, '~~$1~~');

  // Code blocks
  md = md.replace(/<pre[^>]*><code[^>]*>([\s\S]*?)<\/code><\/pre>/gi, '```\n$1\n```');
  md = md.replace(/<pre[^>]*>([\s\S]*?)<\/pre>/gi, '```\n$1\n```');

  // Inline code
  md = md.replace(/<code[^>]*>(.*?)<\/code>/gi, '`$1`');

  // Links
  md = md.replace(/<a[^>]*href="([^"]*)"[^>]*>(.*?)<\/a>/gi, '[$2]($1)');

  // Images
  md = md.replace(/<img[^>]*alt="([^"]*)"[^>]*src="([^"]*)"[^>]*\/?>/gi, '![$1]($2)');
  md = md.replace(/<img[^>]*src="([^"]*)"[^>]*alt="([^"]*)"[^>]*\/?>/gi, '![$2]($1)');
  md = md.replace(/<img[^>]*src="([^"]*)"[^>]*\/?>/gi, '![]($1)');

  // List items
  md = md.replace(/<li[^>]*>(.*?)<\/li>/gi, '- $1\n');

  // Remove list wrappers
  md = md.replace(/<\/?ul[^>]*>/gi, '\n');
  md = md.replace(/<\/?ol[^>]*>/gi, '\n');

  // Blockquotes
  md = md.replace(/<blockquote[^>]*>(.*?)<\/blockquote>/gi, '> $1\n');

  // Horizontal rule
  md = md.replace(/<hr[^>]*\/?>/gi, '\n---\n');

  // Paragraphs
  md = md.replace(/<p[^>]*>(.*?)<\/p>/gi, '$1\n\n');

  // Line breaks
  md = md.replace(/<br[^>]*\/?>/gi, '\n');

  // Remove remaining HTML tags
  md = md.replace(/<[^>]+>/g, '');

  // Decode HTML entities
  md = md.replace(/&nbsp;/g, ' ');
  md = md.replace(/&amp;/g, '&');
  md = md.replace(/&lt;/g, '<');
  md = md.replace(/&gt;/g, '>');
  md = md.replace(/&quot;/g, '"');

  // Clean up extra whitespace
  md = md.replace(/\n{3,}/g, '\n\n');
  md = md.trim();

  return md;
};

const HtmlToMarkdown: React.FC<Props> = ({ data, onChange }) => {
  const input = data.input ?? '';
  const output = data.output ?? '';

  const handleConvert = () => {
    const md = convertHtmlToMarkdown(input);
    onChange({ ...data, output: md });
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(output);
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">HTML Input</label>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value })}
          placeholder="<h1>Heading</h1>&#10;<p><strong>Bold</strong> and <em>italic</em></p>"
          className="w-full h-32 px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-sm resize-none"
        />
      </div>

      <button
        onClick={handleConvert}
        className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded text-sm"
      >
        Convert to Markdown
      </button>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Markdown Output</label>
        <textarea
          readOnly
          value={output}
          placeholder="Markdown output will appear here..."
          className="w-full h-32 px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-green-400 font-mono text-sm resize-none"
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
        Copy Markdown
      </button>
    </div>
  );
};

export class HtmlToMarkdownTool {
  static Component = HtmlToMarkdown;
}
