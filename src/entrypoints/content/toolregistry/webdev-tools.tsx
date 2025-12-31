import React from 'react';
import {
  faBolt,
  faBug,
  faCode,
  faCompress,
  faGear,
  faLink,
  faSquare,
  faCircle,
  faStar,
  faArrowsRotate,
  faFileLines,
  faKeyboard,
  faRuler,
  faPalette,
  faImage,
  faEyeDropper,
  faSliders,
  faTable,
  faEye,
  faTableCells,
  faGlobe
} from '@fortawesome/free-solid-svg-icons';
import {
  CodeInjectorTool,
  LiveLinkPreviewTool,
  DebuggerTool,
  StorageExplorerTool,
  LighthouseSnapshotTool,
  MetaTagGeneratorTool,
  OpenGraphPreviewerTool,
  BoxShadowGeneratorTool,
  BorderRadiusGeneratorTool,
  FaviconGeneratorTool,
  CssGradientGeneratorTool,
  CssFilterGeneratorTool,
  CssTransformGeneratorTool,
  HtmlTableGeneratorTool,
  MarkdownToHtmlTool,
  HtmlToMarkdownTool,
  LoremIpsumGeneratorTool,
  PlaceholderImageTool,
  Base64ImageConverterTool,
  KeycodeInfoTool,
  ClampCalculatorTool,
  ImageCompressorTool,
  ColorPaletteExtractorTool,
  ColorBlindnessSimulatorTool,
  VisualGridBuilderTool
} from '../Tools';
import type {
  CodeInjectorData,
  LiveLinkPreviewData,
  DebuggerData,
  StorageExplorerData,
  LighthouseSnapshotData,
  MetaTagGeneratorData,
  OpenGraphPreviewerData,
  BoxShadowGeneratorData,
  BorderRadiusGeneratorData,
  FaviconGeneratorData,
  CssGradientGeneratorData,
  CssFilterGeneratorData,
  CssTransformGeneratorData,
  HtmlTableGeneratorData,
  MarkdownToHtmlData,
  HtmlToMarkdownData,
  LoremIpsumGeneratorData,
  PlaceholderImageData,
  Base64ImageConverterData,
  KeycodeInfoData,
  ClampCalculatorData,
  ImageCompressorData,
  ColorPaletteExtractorData,
  ColorBlindnessSimulatorData,
  VisualGridBuilderData
} from '../Tools/tool-types';
import type { ToolRegistryEntry, ToolRegistryHandlers } from './types';

export const buildWebDevTools = (handlers: ToolRegistryHandlers): ToolRegistryEntry[] => [
  {
    id: 'codeInjector',
    title: 'CSS Injector',
    subtitle: 'Inject custom CSS',
    category: 'Web Dev',
    icon: faCode,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <CodeInjectorTool.Component
        data={data as CodeInjectorData | undefined}
        onChange={(next) => onChange(next)}
        onInject={async (payload) => {
          await chrome.runtime.sendMessage({
            type: 'xcalibr-inject-code',
            payload
          });
        }}
      />
    )
  },
  {
    id: 'liveLinkPreview',
    title: 'Live Link Preview',
    subtitle: 'Hover link previews',
    category: 'Web Dev',
    icon: faLink,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <LiveLinkPreviewTool.Component
        data={data as LiveLinkPreviewData | undefined}
        onChange={(next) => onChange(next)}
      />
    )
  },
  {
    id: 'debuggerTool',
    title: 'Debugger',
    subtitle: 'Capture errors',
    category: 'Web Dev',
    icon: faBug,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <DebuggerTool.Component
        data={data as DebuggerData | undefined}
        onClear={() => onChange({ entries: [] })}
      />
    )
  },
  {
    id: 'storageExplorer',
    title: 'Storage Explorer',
    subtitle: 'View storage',
    category: 'Web Dev',
    icon: faGear,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    width: 450,
    height: 400,
    render: (data) => (
      <StorageExplorerTool.Component
        data={data as StorageExplorerData | undefined}
        onRefresh={handlers.refreshStorageExplorer}
      />
    )
  },
  {
    id: 'lighthouseSnapshot',
    title: 'Lighthouse Snapshot',
    subtitle: 'Perf metrics',
    category: 'Web Dev',
    icon: faBolt,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <LighthouseSnapshotTool.Component
        data={data as LighthouseSnapshotData | undefined}
        onCapture={() => {
          const timing = performance.timing;
          const paint = performance.getEntriesByType('paint');
          const metrics = [
            { label: 'TTFB', value: `${timing.responseStart - timing.requestStart} ms` },
            { label: 'DOMContentLoaded', value: `${timing.domContentLoadedEventEnd - timing.navigationStart} ms` },
            { label: 'Load', value: `${timing.loadEventEnd - timing.navigationStart} ms` }
          ];
          const firstPaint = paint.find((entry) => entry.name === 'first-contentful-paint');
          if (firstPaint) {
            metrics.push({ label: 'FCP', value: `${Math.round(firstPaint.startTime)} ms` });
          }
          onChange({ metrics });
        }}
      />
    )
  },
  {
    id: 'metaTagGenerator',
    title: 'Meta Tag Generator',
    subtitle: 'SEO meta tags',
    category: 'Web Dev',
    icon: faCode,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <MetaTagGeneratorTool.Component
        data={data as MetaTagGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'openGraphPreviewer',
    title: 'Open Graph Preview',
    subtitle: 'Social media preview',
    category: 'Web Dev',
    icon: faGlobe,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <OpenGraphPreviewerTool.Component
        data={data as OpenGraphPreviewerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'boxShadowGenerator',
    title: 'Box Shadow Generator',
    subtitle: 'CSS box-shadow',
    category: 'Web Dev',
    icon: faSquare,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <BoxShadowGeneratorTool.Component
        data={data as BoxShadowGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'borderRadiusGenerator',
    title: 'Border Radius Generator',
    subtitle: 'CSS border-radius',
    category: 'Web Dev',
    icon: faCircle,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <BorderRadiusGeneratorTool.Component
        data={data as BorderRadiusGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'faviconGenerator',
    title: 'Favicon Generator',
    subtitle: 'Create favicons',
    category: 'Web Dev',
    icon: faStar,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <FaviconGeneratorTool.Component
        data={(data as FaviconGeneratorData) ?? {}}
        onChange={onChange}
      />
    )
  },
  {
    id: 'cssGradientGenerator',
    title: 'CSS Gradient Generator',
    subtitle: 'Create gradients',
    category: 'Web Dev',
    icon: faEyeDropper,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <CssGradientGeneratorTool.Component
        data={(data as CssGradientGeneratorData) ?? {}}
        onChange={onChange}
      />
    )
  },
  {
    id: 'cssFilterGenerator',
    title: 'CSS Filter Generator',
    subtitle: 'Image filters',
    category: 'Web Dev',
    icon: faSliders,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <CssFilterGeneratorTool.Component
        data={(data as CssFilterGeneratorData) ?? {}}
        onChange={onChange}
      />
    )
  },
  {
    id: 'cssTransformGenerator',
    title: 'CSS Transform Generator',
    subtitle: 'Transform elements',
    category: 'Web Dev',
    icon: faArrowsRotate,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <CssTransformGeneratorTool.Component
        data={(data as CssTransformGeneratorData) ?? {}}
        onChange={onChange}
      />
    )
  },
  {
    id: 'htmlTableGenerator',
    title: 'HTML Table Generator',
    subtitle: 'Generate tables',
    category: 'Web Dev',
    icon: faTable,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    width: 450,
    render: (data, onChange) => (
      <HtmlTableGeneratorTool.Component
        data={(data as HtmlTableGeneratorData) ?? {}}
        onChange={onChange}
      />
    )
  },
  {
    id: 'markdownToHtml',
    title: 'Markdown to HTML',
    subtitle: 'Convert markdown',
    category: 'Web Dev',
    icon: faCode,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    width: 400,
    render: (data, onChange) => (
      <MarkdownToHtmlTool.Component
        data={(data as MarkdownToHtmlData) ?? {}}
        onChange={onChange}
      />
    )
  },
  {
    id: 'htmlToMarkdown',
    title: 'HTML to Markdown',
    subtitle: 'Convert HTML',
    category: 'Web Dev',
    icon: faCode,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    width: 400,
    render: (data, onChange) => (
      <HtmlToMarkdownTool.Component
        data={(data as HtmlToMarkdownData) ?? {}}
        onChange={onChange}
      />
    )
  },
  {
    id: 'loremIpsumGenerator',
    title: 'Lorem Ipsum Generator',
    subtitle: 'Placeholder text',
    category: 'Web Dev',
    icon: faFileLines,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <LoremIpsumGeneratorTool.Component
        data={(data as LoremIpsumGeneratorData) ?? {}}
        onChange={onChange}
      />
    )
  },
  {
    id: 'placeholderImage',
    title: 'Placeholder Image',
    subtitle: 'Generate placeholder',
    category: 'Web Dev',
    icon: faImage,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <PlaceholderImageTool.Component
        data={(data as PlaceholderImageData) ?? {}}
        onChange={onChange}
      />
    )
  },
  {
    id: 'base64ImageConverter',
    title: 'Base64 Image Converter',
    subtitle: 'Image/Base64 convert',
    category: 'Web Dev',
    icon: faImage,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <Base64ImageConverterTool.Component
        data={data as Base64ImageConverterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'keycodeInfo',
    title: 'Keycode Info',
    subtitle: 'Key event details',
    category: 'Web Dev',
    icon: faKeyboard,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <KeycodeInfoTool.Component
        data={data as KeycodeInfoData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'clampCalculator',
    title: 'Clamp Calculator',
    subtitle: 'Fluid typography',
    category: 'Web Dev',
    icon: faRuler,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <ClampCalculatorTool.Component
        data={data as ClampCalculatorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'imageCompressor',
    title: 'Image Compressor',
    subtitle: 'Compress images',
    category: 'Web Dev',
    icon: faCompress,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <ImageCompressorTool.Component
        data={data as ImageCompressorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'colorPaletteExtractor',
    title: 'Color Palette Extractor',
    subtitle: 'Extract colors',
    category: 'Web Dev',
    icon: faPalette,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <ColorPaletteExtractorTool.Component
        data={data as ColorPaletteExtractorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'colorBlindnessSimulator',
    title: 'Color Blindness Sim',
    subtitle: 'Simulate vision',
    category: 'Web Dev',
    icon: faEye,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <ColorBlindnessSimulatorTool.Component
        data={data as ColorBlindnessSimulatorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'visualGridBuilder',
    title: 'Visual Grid Builder',
    subtitle: 'Design CSS grids',
    category: 'Web Dev',
    icon: faTableCells,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <VisualGridBuilderTool.Component
        data={data as VisualGridBuilderData | undefined}
        onChange={onChange}
      />
    )
  }
];
