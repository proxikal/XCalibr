import React from 'react';

export type XmlToJsonData = {
  input?: string;
  output?: string;
  error?: string;
};

type Props = {
  data: XmlToJsonData | undefined;
  onChange: (data: XmlToJsonData) => void;
};

const xmlToJson = (xml: string): unknown => {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xml, 'text/xml');

  const parseError = doc.querySelector('parsererror');
  if (parseError) {
    throw new Error('Invalid XML: ' + parseError.textContent?.substring(0, 100));
  }

  const nodeToObj = (node: Element): unknown => {
    const obj: Record<string, unknown> = {};

    // Handle attributes
    if (node.attributes.length > 0) {
      obj['@attributes'] = {};
      for (let i = 0; i < node.attributes.length; i++) {
        const attr = node.attributes[i];
        (obj['@attributes'] as Record<string, string>)[attr.name] = attr.value;
      }
    }

    // Handle children
    const children = Array.from(node.childNodes);
    const elementChildren = children.filter(c => c.nodeType === Node.ELEMENT_NODE) as Element[];
    const textContent = children
      .filter(c => c.nodeType === Node.TEXT_NODE)
      .map(c => c.textContent?.trim())
      .filter(Boolean)
      .join('');

    if (elementChildren.length === 0 && textContent) {
      // Leaf node with text
      if (Object.keys(obj).length === 0) {
        return textContent;
      }
      obj['#text'] = textContent;
    } else {
      // Has element children
      for (const child of elementChildren) {
        const childName = child.tagName;
        const childValue = nodeToObj(child);

        if (childName in obj) {
          // Convert to array if multiple same-named children
          if (!Array.isArray(obj[childName])) {
            obj[childName] = [obj[childName]];
          }
          (obj[childName] as unknown[]).push(childValue);
        } else {
          obj[childName] = childValue;
        }
      }
    }

    return Object.keys(obj).length === 0 ? '' : obj;
  };

  const root = doc.documentElement;
  return { [root.tagName]: nodeToObj(root) };
};

const XmlToJson: React.FC<Props> = ({ data, onChange }) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const error = data?.error ?? '';

  const handleConvert = () => {
    try {
      const result = xmlToJson(input);
      onChange({
        ...data,
        output: JSON.stringify(result, null, 2),
        error: ''
      });
    } catch (e) {
      onChange({
        ...data,
        output: '',
        error: e instanceof Error ? e.message : 'Conversion failed'
      });
    }
  };

  const copyOutput = () => {
    if (output) {
      navigator.clipboard.writeText(output);
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">XML Input</label>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value })}
          placeholder="<root>&#10;  <item>value</item>&#10;</root>"
          rows={8}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
        />
      </div>

      <button
        onClick={handleConvert}
        disabled={!input.trim()}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
      >
        Convert to JSON
      </button>

      {error && (
        <div className="text-red-400 text-xs p-2 bg-red-900/20 rounded">{error}</div>
      )}

      {output && (
        <div>
          <div className="flex justify-between items-center mb-1">
            <label className="text-xs text-gray-400">JSON Output</label>
            <button
              onClick={copyOutput}
              className="text-xs text-blue-400 hover:text-blue-300"
            >
              Copy
            </button>
          </div>
          <textarea
            value={output}
            readOnly
            rows={10}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-green-400 font-mono text-xs resize-none"
          />
        </div>
      )}
    </div>
  );
};

export class XmlToJsonTool {
  static Component = XmlToJson;
}
