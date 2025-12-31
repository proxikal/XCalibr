import React from 'react';
import {
  faFileExcel,
  faTextHeight,
  faCalculator,
  faListOl,
  faShuffle,
  faCodeCompare,
  faFileCode,
  faFileAlt,
  faFileExport,
  faMask,
  faCode,
  faMemory,
  faIcons,
  faHighlighter,
  faShieldAlt,
  faClock,
  faGlobeAmericas,
  faExchangeAlt,
  faRulerCombined,
  faFingerprint,
  faDatabase,
  faCodeBranch,
  faBalanceScale,
  faCompress,
  faPalette,
  faCubes,
  faTable,
  faTerminal,
  faQrcode,
  faBarcode,
  faStopwatch,
  faStickyNote,
  faListCheck
} from '@fortawesome/free-solid-svg-icons';
import {
  CsvToJsonTool,
  CaseConverterTool,
  TextStatisticsTool,
  LineSorterTool,
  ListRandomizerTool,
  TextDiffTool,
  XmlToJsonTool,
  YamlToJsonTool,
  JsonToYamlTool,
  StringObfuscatorTool,
  TextToBinaryTool,
  HexViewerTool,
  UnicodeExplorerTool,
  RegexHighlighterTool,
  EscapingTool,
  UnixTimestampTool,
  TimezoneConverterTool,
  UnitConverterTool,
  AspectRatioCalculatorTool,
  UuidGeneratorTool,
  ObjectIdGeneratorTool,
  GitCommandBuilderTool,
  GitIgnoreGeneratorTool,
  LicenseGeneratorTool,
  JsMinifierTool,
  CssMinifierTool,
  PythonToJsonTool,
  TypescriptInterfaceGenTool,
  GoStructGeneratorTool,
  SqlSchemaGeneratorTool,
  CurlToFetchTool,
  QrCodeGeneratorTool,
  BarcodeGeneratorTool,
  StopwatchTimerTool,
  PomodoroTimerTool,
  ScratchpadTool,
  TodoListTool,
  MathEvaluatorTool
} from '../Tools';
import type {
  CsvToJsonData,
  CaseConverterData,
  TextStatisticsData,
  LineSorterData,
  ListRandomizerData,
  TextDiffData,
  XmlToJsonData,
  YamlToJsonData,
  JsonToYamlData,
  StringObfuscatorData,
  TextToBinaryData,
  HexViewerData,
  UnicodeExplorerData,
  RegexHighlighterData,
  EscapingToolData,
  UnixTimestampData,
  TimezoneConverterData,
  UnitConverterData,
  AspectRatioCalculatorData,
  UuidGeneratorData,
  ObjectIdGeneratorData,
  GitCommandBuilderData,
  GitIgnoreGeneratorData,
  LicenseGeneratorData,
  JsMinifierData,
  CssMinifierData,
  PythonToJsonData,
  TypescriptInterfaceGenData,
  GoStructGeneratorData,
  SqlSchemaGeneratorData,
  CurlToFetchData,
  QrCodeGeneratorData,
  BarcodeGeneratorData,
  StopwatchTimerData,
  PomodoroTimerData,
  ScratchpadData,
  TodoListData,
  MathEvaluatorData
} from '../Tools/tool-types';
import type { ToolRegistryEntry } from './types';

export const buildDataTextTools = (): ToolRegistryEntry[] => [
  {
    id: 'csvToJson',
    title: 'CSV to JSON',
    subtitle: 'Convert CSV data',
    category: 'Data & Text',
    icon: faFileExcel,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <CsvToJsonTool.Component
        data={data as CsvToJsonData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'caseConverter',
    title: 'Case Converter',
    subtitle: 'Convert text case',
    category: 'Data & Text',
    icon: faTextHeight,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <CaseConverterTool.Component
        data={data as CaseConverterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'textStatistics',
    title: 'Text Statistics',
    subtitle: 'Count words/chars',
    category: 'Data & Text',
    icon: faCalculator,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <TextStatisticsTool.Component
        data={data as TextStatisticsData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'lineSorter',
    title: 'Line Sorter',
    subtitle: 'Sort/dedupe lines',
    category: 'Data & Text',
    icon: faListOl,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <LineSorterTool.Component
        data={data as LineSorterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'listRandomizer',
    title: 'List Randomizer',
    subtitle: 'Shuffle/pick random',
    category: 'Data & Text',
    icon: faShuffle,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <ListRandomizerTool.Component
        data={data as ListRandomizerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'textDiff',
    title: 'Text Diff',
    subtitle: 'Compare texts',
    category: 'Data & Text',
    icon: faCodeCompare,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <TextDiffTool.Component
        data={data as TextDiffData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'xmlToJson',
    title: 'XML to JSON',
    subtitle: 'Convert XML data',
    category: 'Data & Text',
    icon: faFileCode,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <XmlToJsonTool.Component
        data={data as XmlToJsonData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'yamlToJson',
    title: 'YAML to JSON',
    subtitle: 'Convert YAML data',
    category: 'Data & Text',
    icon: faFileAlt,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <YamlToJsonTool.Component
        data={data as YamlToJsonData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'jsonToYaml',
    title: 'JSON to YAML',
    subtitle: 'Convert JSON data',
    category: 'Data & Text',
    icon: faFileExport,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <JsonToYamlTool.Component
        data={data as JsonToYamlData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'stringObfuscator',
    title: 'String Obfuscator',
    subtitle: 'Obfuscate strings',
    category: 'Data & Text',
    icon: faMask,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <StringObfuscatorTool.Component
        data={data as StringObfuscatorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'textToBinary',
    title: 'Text to Binary',
    subtitle: 'Convert text/binary',
    category: 'Data & Text',
    icon: faCode,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <TextToBinaryTool.Component
        data={data as TextToBinaryData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'hexViewer',
    title: 'Hex Viewer',
    subtitle: 'View hex dump',
    category: 'Data & Text',
    icon: faMemory,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <HexViewerTool.Component
        data={data as HexViewerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'unicodeExplorer',
    title: 'Unicode Explorer',
    subtitle: 'Browse characters',
    category: 'Data & Text',
    icon: faIcons,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <UnicodeExplorerTool.Component
        data={data as UnicodeExplorerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'regexHighlighter',
    title: 'Regex Highlighter',
    subtitle: 'Test & highlight matches',
    category: 'Data & Text',
    icon: faHighlighter,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <RegexHighlighterTool.Component
        data={data as RegexHighlighterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'escapingTool',
    title: 'Escaping Tool',
    subtitle: 'Escape strings',
    category: 'Data & Text',
    icon: faShieldAlt,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <EscapingTool.Component
        data={data as EscapingToolData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'unixTimestamp',
    title: 'Unix Timestamp',
    subtitle: 'Convert timestamps',
    category: 'Data & Text',
    icon: faClock,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <UnixTimestampTool.Component
        data={data as UnixTimestampData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'timezoneConverter',
    title: 'Timezone Converter',
    subtitle: 'Convert timezones',
    category: 'Data & Text',
    icon: faGlobeAmericas,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <TimezoneConverterTool.Component
        data={data as TimezoneConverterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'unitConverter',
    title: 'Unit Converter',
    subtitle: 'Convert dev units',
    category: 'Data & Text',
    icon: faExchangeAlt,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <UnitConverterTool.Component
        data={data as UnitConverterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'aspectRatioCalculator',
    title: 'Aspect Ratio Calculator',
    subtitle: 'Calculate ratios',
    category: 'Data & Text',
    icon: faRulerCombined,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <AspectRatioCalculatorTool.Component
        data={data as AspectRatioCalculatorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'uuidGenerator',
    title: 'UUID Generator',
    subtitle: 'Generate UUIDs',
    category: 'Data & Text',
    icon: faFingerprint,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <UuidGeneratorTool.Component
        data={data as UuidGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'objectIdGenerator',
    title: 'ObjectId Generator',
    subtitle: 'MongoDB ObjectIds',
    category: 'Data & Text',
    icon: faDatabase,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <ObjectIdGeneratorTool.Component
        data={data as ObjectIdGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'gitCommandBuilder',
    title: 'Git Command Builder',
    subtitle: 'Build git commands',
    category: 'Data & Text',
    icon: faCodeBranch,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <GitCommandBuilderTool.Component
        data={data as GitCommandBuilderData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'gitignoreGenerator',
    title: 'GitIgnore Generator',
    subtitle: 'Generate .gitignore',
    category: 'Data & Text',
    icon: faFileAlt,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <GitIgnoreGeneratorTool.Component
        data={data as GitIgnoreGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'licenseGenerator',
    title: 'License Generator',
    subtitle: 'Generate licenses',
    category: 'Data & Text',
    icon: faBalanceScale,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <LicenseGeneratorTool.Component
        data={data as LicenseGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'jsMinifier',
    title: 'JS Minifier',
    subtitle: 'Minify JavaScript',
    category: 'Data & Text',
    icon: faCompress,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <JsMinifierTool.Component
        data={data as JsMinifierData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'cssMinifier',
    title: 'CSS Minifier',
    subtitle: 'Minify CSS',
    category: 'Data & Text',
    icon: faPalette,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <CssMinifierTool.Component
        data={data as CssMinifierData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'pythonToJson',
    title: 'Python to JSON',
    subtitle: 'Convert Python dict',
    category: 'Data & Text',
    icon: faFileCode,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <PythonToJsonTool.Component
        data={data as PythonToJsonData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'typescriptInterfaceGen',
    title: 'TypeScript Interface',
    subtitle: 'Generate TS interfaces',
    category: 'Data & Text',
    icon: faCode,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <TypescriptInterfaceGenTool.Component
        data={data as TypescriptInterfaceGenData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'goStructGenerator',
    title: 'Go Struct Generator',
    subtitle: 'Generate Go structs',
    category: 'Data & Text',
    icon: faCubes,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <GoStructGeneratorTool.Component
        data={data as GoStructGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'sqlSchemaGenerator',
    title: 'SQL Schema Generator',
    subtitle: 'Generate SQL CREATE',
    category: 'Data & Text',
    icon: faTable,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <SqlSchemaGeneratorTool.Component
        data={data as SqlSchemaGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'curlToFetch',
    title: 'cURL to Fetch',
    subtitle: 'Convert cURL to JS',
    category: 'Data & Text',
    icon: faTerminal,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <CurlToFetchTool.Component
        data={data as CurlToFetchData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'qrCodeGenerator',
    title: 'QR Code Generator',
    subtitle: 'Generate QR codes',
    category: 'Data & Text',
    icon: faQrcode,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <QrCodeGeneratorTool.Component
        data={data as QrCodeGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'barcodeGenerator',
    title: 'Barcode Generator',
    subtitle: 'Generate barcodes',
    category: 'Data & Text',
    icon: faBarcode,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <BarcodeGeneratorTool.Component
        data={data as BarcodeGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'stopwatchTimer',
    title: 'Stopwatch / Timer',
    subtitle: 'Time tracking',
    category: 'Data & Text',
    icon: faStopwatch,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <StopwatchTimerTool.Component
        data={data as StopwatchTimerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'pomodoroTimer',
    title: 'Pomodoro Timer',
    subtitle: 'Focus timer',
    category: 'Data & Text',
    icon: faClock,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <PomodoroTimerTool.Component
        data={data as PomodoroTimerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'scratchpad',
    title: 'Scratchpad',
    subtitle: 'Persistent notes',
    category: 'Data & Text',
    icon: faStickyNote,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <ScratchpadTool.Component
        data={data as ScratchpadData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'todoList',
    title: 'Todo List',
    subtitle: 'Task manager',
    category: 'Data & Text',
    icon: faListCheck,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <TodoListTool.Component
        data={data as TodoListData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'mathEvaluator',
    title: 'Math Evaluator',
    subtitle: 'Calculate expressions',
    category: 'Data & Text',
    icon: faCalculator,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <MathEvaluatorTool.Component
        data={data as MathEvaluatorData | undefined}
        onChange={onChange}
      />
    )
  }
];
