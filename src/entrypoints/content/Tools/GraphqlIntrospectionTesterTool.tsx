import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faPlay, faExclamationTriangle, faCheckCircle, faCopy, faChevronDown, faChevronRight } from '@fortawesome/free-solid-svg-icons';

export type GraphqlIntrospectionTesterData = {
  url?: string;
  isEnabled?: boolean;
  schema?: {
    types?: string[];
    queryFields?: string[];
    mutationFields?: string[];
    subscriptionFields?: string[];
  };
  rawResponse?: string;
  testedAt?: number;
  isTesting?: boolean;
  error?: string;
};

type Props = {
  data: GraphqlIntrospectionTesterData | undefined;
  onChange: (data: GraphqlIntrospectionTesterData) => void;
};

const INTROSPECTION_QUERY = `query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}`;

const GraphqlIntrospectionTester: React.FC<Props> = ({ data, onChange }) => {
  const url = data?.url ?? '';
  const isEnabled = data?.isEnabled;
  const schema = data?.schema;
  const testedAt = data?.testedAt;
  const isTesting = data?.isTesting ?? false;
  const error = data?.error ?? '';

  const [copied, setCopied] = useState(false);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    types: true,
    queries: true,
    mutations: false,
    subscriptions: false
  });

  const handleTest = async () => {
    if (!url.trim()) return;

    onChange({ ...data, isTesting: true, error: '', isEnabled: undefined, schema: undefined });

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ query: INTROSPECTION_QUERY })
      });

      const result = await response.json();

      if (result.errors && result.errors.length > 0) {
        // Check if introspection is disabled
        const isDisabled = result.errors.some((e: { message: string }) =>
          e.message.toLowerCase().includes('introspection') ||
          e.message.toLowerCase().includes('disabled') ||
          e.message.toLowerCase().includes('not allowed')
        );

        if (isDisabled) {
          onChange({
            ...data,
            isEnabled: false,
            testedAt: Date.now(),
            isTesting: false,
            error: ''
          });
          return;
        }

        throw new Error(result.errors[0].message);
      }

      if (result.data?.__schema) {
        const schemaData = result.data.__schema;

        // Extract type names (excluding built-in types)
        const types = schemaData.types
          ?.filter((t: { name: string }) => !t.name.startsWith('__'))
          ?.map((t: { name: string }) => t.name) || [];

        // Find query type and its fields
        const queryTypeName = schemaData.queryType?.name || 'Query';
        const queryType = schemaData.types?.find((t: { name: string }) => t.name === queryTypeName);
        const queryFields = queryType?.fields?.map((f: { name: string }) => f.name) || [];

        // Find mutation type and its fields
        const mutationTypeName = schemaData.mutationType?.name;
        const mutationType = mutationTypeName
          ? schemaData.types?.find((t: { name: string }) => t.name === mutationTypeName)
          : null;
        const mutationFields = mutationType?.fields?.map((f: { name: string }) => f.name) || [];

        // Find subscription type and its fields
        const subscriptionTypeName = schemaData.subscriptionType?.name;
        const subscriptionType = subscriptionTypeName
          ? schemaData.types?.find((t: { name: string }) => t.name === subscriptionTypeName)
          : null;
        const subscriptionFields = subscriptionType?.fields?.map((f: { name: string }) => f.name) || [];

        onChange({
          ...data,
          isEnabled: true,
          schema: {
            types,
            queryFields,
            mutationFields,
            subscriptionFields
          },
          rawResponse: JSON.stringify(result, null, 2),
          testedAt: Date.now(),
          isTesting: false,
          error: ''
        });
      } else {
        throw new Error('Invalid GraphQL response');
      }
    } catch (e) {
      onChange({
        ...data,
        isTesting: false,
        error: e instanceof Error ? e.message : 'Failed to test introspection'
      });
    }
  };

  const handleCopyQuery = () => {
    navigator.clipboard.writeText(INTROSPECTION_QUERY);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const toggleSection = (section: string) => {
    setExpandedSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">GraphQL Introspection</div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Tests if GraphQL introspection is enabled on an endpoint, revealing the full schema.
      </div>

      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
        <div className="text-[10px] text-slate-500 mb-1">GraphQL Endpoint</div>
        <input
          type="url"
          value={url}
          onChange={(e) => onChange({ ...data, url: e.target.value })}
          placeholder="https://example.com/graphql"
          className="w-full rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-purple-500"
        />
      </div>

      <button
        onClick={handleTest}
        disabled={!url.trim() || isTesting}
        className="w-full rounded bg-purple-600/20 border border-purple-500/30 px-2 py-1.5 text-[11px] text-purple-300 hover:bg-purple-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={faPlay} className="w-3 h-3" />
        {isTesting ? 'Testing...' : 'Test Introspection'}
      </button>

      {error && (
        <div className="text-red-400 text-[10px] bg-red-900/20 border border-red-500/30 p-2 rounded mb-3">
          {error}
        </div>
      )}

      {testedAt && isEnabled !== undefined && (
        <div className={`p-2 rounded mb-3 ${
          isEnabled
            ? 'bg-red-900/20 border border-red-500/30'
            : 'bg-green-900/20 border border-green-500/30'
        }`}>
          <div className={`flex items-center gap-2 font-medium text-[11px] ${
            isEnabled ? 'text-red-400' : 'text-green-400'
          }`}>
            <FontAwesomeIcon icon={isEnabled ? faExclamationTriangle : faCheckCircle} className="w-3 h-3" />
            <span>{isEnabled ? 'Introspection Enabled (Vulnerable)' : 'Introspection Disabled'}</span>
          </div>
          <div className="text-[10px] text-slate-300 mt-1">
            {isEnabled
              ? 'The endpoint exposes its full GraphQL schema through introspection.'
              : 'The endpoint has properly disabled introspection queries.'}
          </div>
        </div>
      )}

      <div className="flex-1 overflow-y-auto space-y-2 min-h-0">
        {isEnabled && schema && (
          <>
            {/* Types */}
            {schema.types && schema.types.length > 0 && (
              <div className="border border-slate-700 rounded">
                <button
                  onClick={() => toggleSection('types')}
                  className="w-full px-2 py-1.5 flex items-center justify-between text-[11px] text-slate-300 hover:bg-slate-800/50 transition-colors"
                >
                  <span>Types ({schema.types.length})</span>
                  <FontAwesomeIcon icon={expandedSections.types ? faChevronDown : faChevronRight} className="w-2.5 h-2.5" />
                </button>
                {expandedSections.types && (
                  <div className="px-2 py-2 border-t border-slate-700 max-h-28 overflow-y-auto">
                    <div className="flex flex-wrap gap-1">
                      {schema.types.map((type, i) => (
                        <span key={i} className="px-1.5 py-0.5 bg-blue-900/30 text-blue-400 rounded text-[9px]">
                          {type}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Query Fields */}
            {schema.queryFields && schema.queryFields.length > 0 && (
              <div className="border border-slate-700 rounded">
                <button
                  onClick={() => toggleSection('queries')}
                  className="w-full px-2 py-1.5 flex items-center justify-between text-[11px] text-slate-300 hover:bg-slate-800/50 transition-colors"
                >
                  <span>Query Fields ({schema.queryFields.length})</span>
                  <FontAwesomeIcon icon={expandedSections.queries ? faChevronDown : faChevronRight} className="w-2.5 h-2.5" />
                </button>
                {expandedSections.queries && (
                  <div className="px-2 py-2 border-t border-slate-700 max-h-28 overflow-y-auto">
                    <div className="flex flex-wrap gap-1">
                      {schema.queryFields.map((field, i) => (
                        <span key={i} className="px-1.5 py-0.5 bg-green-900/30 text-green-400 rounded text-[9px] font-mono">
                          {field}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Mutation Fields */}
            {schema.mutationFields && schema.mutationFields.length > 0 && (
              <div className="border border-slate-700 rounded">
                <button
                  onClick={() => toggleSection('mutations')}
                  className="w-full px-2 py-1.5 flex items-center justify-between text-[11px] text-slate-300 hover:bg-slate-800/50 transition-colors"
                >
                  <span>Mutation Fields ({schema.mutationFields.length})</span>
                  <FontAwesomeIcon icon={expandedSections.mutations ? faChevronDown : faChevronRight} className="w-2.5 h-2.5" />
                </button>
                {expandedSections.mutations && (
                  <div className="px-2 py-2 border-t border-slate-700 max-h-28 overflow-y-auto">
                    <div className="flex flex-wrap gap-1">
                      {schema.mutationFields.map((field, i) => (
                        <span key={i} className="px-1.5 py-0.5 bg-yellow-900/30 text-yellow-400 rounded text-[9px] font-mono">
                          {field}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </>
        )}

        <div className="border-t border-slate-700 pt-2">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] text-slate-500">Introspection Query</span>
            <button
              onClick={handleCopyQuery}
              className="rounded bg-slate-800 px-2 py-0.5 text-[9px] text-slate-400 hover:text-slate-300 border border-slate-700 flex items-center gap-1 transition-colors"
            >
              <FontAwesomeIcon icon={faCopy} className="w-2.5 h-2.5" />
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <pre className="text-[9px] text-slate-500 bg-slate-800/50 border border-slate-700 p-2 rounded overflow-x-auto max-h-20">
            {INTROSPECTION_QUERY}
          </pre>
        </div>
      </div>

      <div className="text-[10px] text-slate-500 space-y-0.5 border-t border-slate-700 pt-2 mt-3">
        <div><strong>Security Risk:</strong> Enabled introspection reveals:</div>
        <ul className="list-disc list-inside ml-2 text-[9px]">
          <li>All available queries, mutations, and subscriptions</li>
          <li>Complete type definitions and relationships</li>
          <li>Field names that may hint at sensitive data</li>
        </ul>
      </div>
    </div>
  );
};

export class GraphqlIntrospectionTesterTool {
  static Component = GraphqlIntrospectionTester;
}
