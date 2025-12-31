import React from 'react';
import {
  faTable,
  faSliders,
  faFont,
  faEyeDropper,
  faExpand,
  faWaveSquare,
  faFileCode,
  faShieldHalved
} from '@fortawesome/free-solid-svg-icons';
import {
  CssGridGeneratorTool,
  FlexboxInspectorTool,
  FontIdentifierTool,
  ContrastCheckerTool,
  ResponsivePreviewTool,
  AnimationPreviewTool,
  SvgOptimizerTool,
  AccessibilityAuditTool,
  ColorPickerTool
} from '../Tools';
import type {
  CssGridGeneratorData,
  FlexboxInspectorData,
  FontIdentifierData,
  ContrastCheckerData,
  ResponsivePreviewData,
  AnimationPreviewData,
  SvgOptimizerData,
  AccessibilityAuditData
} from '../Tools/tool-types';
import { auditAccessibility } from '../Tools/helpers';
import type { ToolRegistryEntry } from './types';

export const buildFrontendTools = (): ToolRegistryEntry[] => [
  {
    id: 'cssGridGenerator',
    title: 'CSS Grid Generator',
    subtitle: 'Grid CSS',
    category: 'Front End',
    icon: faTable,
    hover: 'group-hover:border-blue-500 group-hover:text-blue-400',
    render: (data, onChange) => (
      <CssGridGeneratorTool.Component
        data={data as CssGridGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'flexboxInspector',
    title: 'Flexbox Inspector',
    subtitle: 'Inspect flex',
    category: 'Front End',
    icon: faSliders,
    hover: 'group-hover:border-blue-500 group-hover:text-blue-400',
    render: (data, onChange) => (
      <FlexboxInspectorTool.Component
        data={data as FlexboxInspectorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'fontIdentifier',
    title: 'Font Identifier',
    subtitle: 'Font details',
    category: 'Front End',
    icon: faFont,
    hover: 'group-hover:border-blue-500 group-hover:text-blue-400',
    render: (data, onChange) => (
      <FontIdentifierTool.Component
        data={data as FontIdentifierData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'contrastChecker',
    title: 'Contrast Checker',
    subtitle: 'WCAG ratio',
    category: 'Front End',
    icon: faEyeDropper,
    hover: 'group-hover:border-blue-500 group-hover:text-blue-400',
    render: (data, onChange) => (
      <ContrastCheckerTool.Component
        data={data as ContrastCheckerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'responsivePreview',
    title: 'Responsive Preview',
    subtitle: 'Viewport size',
    category: 'Front End',
    icon: faExpand,
    hover: 'group-hover:border-blue-500 group-hover:text-blue-400',
    render: (data, onChange) => (
      <ResponsivePreviewTool.Component
        data={data as ResponsivePreviewData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'animationPreview',
    title: 'Animation Preview',
    subtitle: 'Preview motion',
    category: 'Front End',
    icon: faWaveSquare,
    hover: 'group-hover:border-blue-500 group-hover:text-blue-400',
    render: (data, onChange) => (
      <AnimationPreviewTool.Component
        data={data as AnimationPreviewData | undefined}
        onChange={onChange}
        onInject={async (css) => {
          await chrome.runtime.sendMessage({
            type: 'xcalibr-inject-code',
            payload: { scope: 'current', code: css }
          });
        }}
      />
    )
  },
  {
    id: 'svgOptimizer',
    title: 'SVG Optimizer',
    subtitle: 'Minify SVG',
    category: 'Front End',
    icon: faFileCode,
    hover: 'group-hover:border-blue-500 group-hover:text-blue-400',
    render: (data, onChange) => (
      <SvgOptimizerTool.Component
        data={data as SvgOptimizerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'accessibilityAudit',
    title: 'Accessibility Audit',
    subtitle: 'Basic checks',
    category: 'Front End',
    icon: faShieldHalved,
    hover: 'group-hover:border-blue-500 group-hover:text-blue-400',
    render: (data, onChange) => (
      <AccessibilityAuditTool.Component
        data={data as AccessibilityAuditData | undefined}
        onRun={() => onChange({ issues: auditAccessibility(document) })}
      />
    )
  },
  {
    id: 'colorPicker',
    title: 'Color Picker',
    subtitle: 'Grab hex/rgb',
    category: 'Front End',
    icon: faEyeDropper,
    hover: 'group-hover:border-blue-500 group-hover:text-blue-400',
    render: (data, onChange) => (
      <ColorPickerTool.Component
        data={data as { color?: string } | undefined}
        onChange={(next) => onChange(next)}
      />
    )
  }
];
