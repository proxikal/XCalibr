import React from 'react';

export type MarkdownToHtmlData = {
  input?: string;
  output?: string;
};

type Props = {
  data: MarkdownToHtmlData;
  onChange: (data: MarkdownToHtmlData) => void;
};

const convertMarkdownToHtml = (markdown: string): string => {
  let html = markdown;

  // Headers
  html = html.replace(/^###### (.*$)/gim, '<h6>$1</h6>');
  html = html.replace(/^##### (.*$)/gim, '<h5>$1</h5>');
  html = html.replace(/^#### (.*$)/gim, '<h4>$1</h4>');
  html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
  html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
  html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');

  // Bold
  html = html.replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>');
  html = html.replace(/__(.*?)__/gim, '<strong>$1</strong>');

  // Italic
  html = html.replace(/\*(.*?)\*/gim, '<em>$1</em>');
  html = html.replace(/_(.*?)_/gim, '<em>$1</em>');

  // Strikethrough
  html = html.replace(/~~(.*?)~~/gim, '<del>$1</del>');

  // Code blocks
  html = html.replace(/```([\s\S]*?)```/gim, '<pre><code>$1</code></pre>');

  // Inline code
  html = html.replace(/`(.*?)`/gim, '<code>$1</code>');

  // Links
  html = html.replace(/\[(.*?)\]\((.*?)\)/gim, '<a href="$2">$1</a>');

  // Images
  html = html.replace(/!\[(.*?)\]\((.*?)\)/gim, '<img alt="$1" src="$2" />');

  // Unordered lists
  html = html.replace(/^\* (.*$)/gim, '<li>$1</li>');
  html = html.replace(/^- (.*$)/gim, '<li>$1</li>');

  // Ordered lists
  html = html.replace(/^\d+\. (.*$)/gim, '<li>$1</li>');

  // Blockquotes
  html = html.replace(/^> (.*$)/gim, '<blockquote>$1</blockquote>');

  // Horizontal rule
  html = html.replace(/^---$/gim, '<hr />');

  // Line breaks
  html = html.replace(/\n\n/gim, '</p><p>');
  html = html.replace(/\n/gim, '<br />');

  // Wrap in paragraphs if needed
  if (!html.startsWith('<')) {
    html = '<p>' + html + '</p>';
  }

  return html;
};

const MarkdownToHtml: React.FC<Props> = ({ data, onChange }) => {
  const input = data.input ?? '';
  const output = data.output ?? '';

  const handleConvert = () => {
    const html = convertMarkdownToHtml(input);
    onChange({ ...data, output: html });
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(output);
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">Markdown Input</label>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value })}
          placeholder="# Heading&#10;&#10;**Bold** and *italic*&#10;&#10;- List item 1&#10;- List item 2"
          className="w-full h-32 px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-sm resize-none"
        />
      </div>

      <button
        onClick={handleConvert}
        className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded text-sm"
      >
        Convert to HTML
      </button>

      <div>
        <label className="block text-xs text-gray-400 mb-1">HTML Output</label>
        <textarea
          readOnly
          value={output}
          placeholder="HTML output will appear here..."
          className="w-full h-32 px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-green-400 font-mono text-xs resize-none"
        />
      </div>

      {output && (
        <div>
          <label className="block text-xs text-gray-400 mb-1">Preview</label>
          <div
            className="p-4 bg-white rounded text-black prose prose-sm max-h-40 overflow-auto"
            dangerouslySetInnerHTML={{ __html: output }}
          />
        </div>
      )}

      <button
        onClick={copyToClipboard}
        disabled={!output}
        className={`w-full py-2 rounded text-sm ${
          output
            ? 'bg-gray-700 hover:bg-gray-600 text-white'
            : 'bg-gray-800 text-gray-500 cursor-not-allowed'
        }`}
      >
        Copy HTML
      </button>
    </div>
  );
};

export class MarkdownToHtmlTool {
  static Component = MarkdownToHtml;
}
