import React from 'react';
import { faCompress, faCode } from '@fortawesome/free-solid-svg-icons';
import {
  JsonMinifierTool,
  JsonPrettifierTool,
  JsonSchemaValidatorTool,
  JsonPathTesterTool,
  JsonDiffTool,
  SqlFormatterTool,
  SqlQueryBuilderTool,
  SqlToCsvTool,
  IndexAdvisorTool,
  BsonViewerTool,
  MongoQueryBuilderTool,
  DynamoDbConverterTool,
  FirebaseRulesLinterTool,
  CouchDbDocExplorerTool
} from '../Tools';
import type {
  JsonMinifierData,
  JsonPrettifierData,
  JsonSchemaValidatorData,
  JsonPathTesterData,
  JsonDiffData,
  SqlFormatterData,
  SqlQueryBuilderData,
  SqlToCsvData,
  IndexAdvisorData,
  BsonViewerData,
  MongoQueryBuilderData,
  DynamoDbConverterData,
  FirebaseRulesLinterData,
  CouchDbDocExplorerData
} from '../Tools/tool-types';
import type { ToolRegistryEntry } from './types';

export const buildDatabaseTools = (): ToolRegistryEntry[] => [
  {
    id: 'jsonMinifier',
    title: 'JSON Minifier',
    subtitle: 'Compress JSON',
    category: 'Database',
    icon: faCompress,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <JsonMinifierTool.Component
        data={data as JsonMinifierData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'jsonPrettifier',
    title: 'JSON Prettifier',
    subtitle: 'Format JSON',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <JsonPrettifierTool.Component
        data={data as JsonPrettifierData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'jsonSchemaValidator',
    title: 'JSON Schema Validator',
    subtitle: 'Validate JSON',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <JsonSchemaValidatorTool.Component
        data={data as JsonSchemaValidatorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'jsonPathTester',
    title: 'JSON Path Tester',
    subtitle: 'Query JSON',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <JsonPathTesterTool.Component
        data={data as JsonPathTesterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'jsonDiff',
    title: 'JSON Diff',
    subtitle: 'Compare JSON',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <JsonDiffTool.Component
        data={data as JsonDiffData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'sqlFormatter',
    title: 'SQL Formatter',
    subtitle: 'Format SQL',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <SqlFormatterTool.Component
        data={data as SqlFormatterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'sqlQueryBuilder',
    title: 'SQL Query Builder',
    subtitle: 'Build SELECT',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <SqlQueryBuilderTool.Component
        data={data as SqlQueryBuilderData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'sqlToCsv',
    title: 'SQL to CSV',
    subtitle: 'Export results',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <SqlToCsvTool.Component
        data={data as SqlToCsvData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'indexAdvisor',
    title: 'Index Advisor',
    subtitle: 'Suggest indexes',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <IndexAdvisorTool.Component
        data={data as IndexAdvisorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'bsonViewer',
    title: 'BSON Viewer',
    subtitle: 'Normalize BSON',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <BsonViewerTool.Component
        data={data as BsonViewerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'mongoQueryBuilder',
    title: 'Mongo Query Builder',
    subtitle: 'Build Mongo find',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <MongoQueryBuilderTool.Component
        data={data as MongoQueryBuilderData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'dynamoDbConverter',
    title: 'DynamoDB Converter',
    subtitle: 'Map JSON types',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <DynamoDbConverterTool.Component
        data={data as DynamoDbConverterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'firebaseRulesLinter',
    title: 'Firebase Rules Linter',
    subtitle: 'Check rules',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <FirebaseRulesLinterTool.Component
        data={data as FirebaseRulesLinterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'couchDbDocExplorer',
    title: 'CouchDB Doc Explorer',
    subtitle: 'Fetch docs',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <CouchDbDocExplorerTool.Component
        data={data as CouchDbDocExplorerData | undefined}
        onChange={onChange}
      />
    )
  }
];
