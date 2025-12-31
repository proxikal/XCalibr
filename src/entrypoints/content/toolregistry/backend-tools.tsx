import React from 'react';
import {
  faCode,
  faWaveSquare,
  faGlobe,
  faNetworkWired,
  faFingerprint,
  faGear
} from '@fortawesome/free-solid-svg-icons';
import {
  JwtDebuggerTool,
  RegexTesterTool,
  ApiResponseViewerTool,
  GraphqlExplorerTool,
  RestClientTool,
  OAuthTokenInspectorTool,
  WebhookTesterTool,
  CookieManagerTool
} from '../Tools';
import type {
  JwtDebuggerData,
  RegexTesterData,
  ApiResponseViewerData,
  GraphqlExplorerData,
  RestClientData,
  OAuthTokenInspectorData,
  WebhookTesterData,
  CookieManagerData
} from '../Tools/tool-types';
import type { ToolRegistryEntry, ToolRegistryHandlers } from './types';

export const buildBackendTools = (handlers: ToolRegistryHandlers): ToolRegistryEntry[] => [
  {
    id: 'jwtDebugger',
    title: 'JWT Debugger',
    subtitle: 'Decode JWT',
    category: 'Back End',
    icon: faCode,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <JwtDebuggerTool.Component
        data={data as JwtDebuggerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'regexTester',
    title: 'Regex Tester',
    subtitle: 'Test patterns',
    category: 'Back End',
    icon: faWaveSquare,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <RegexTesterTool.Component
        data={data as RegexTesterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'apiResponseViewer',
    title: 'API Response Viewer',
    subtitle: 'Inspect API',
    category: 'Back End',
    icon: faGlobe,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <ApiResponseViewerTool.Component
        data={data as ApiResponseViewerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'graphqlExplorer',
    title: 'GraphQL Explorer',
    subtitle: 'Run queries',
    category: 'Back End',
    icon: faCode,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <GraphqlExplorerTool.Component
        data={data as GraphqlExplorerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'restClient',
    title: 'REST Client',
    subtitle: 'Send requests',
    category: 'Back End',
    icon: faNetworkWired,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <RestClientTool.Component
        data={data as RestClientData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'oauthTokenInspector',
    title: 'OAuth Token Inspector',
    subtitle: 'Inspect token',
    category: 'Back End',
    icon: faFingerprint,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <OAuthTokenInspectorTool.Component
        data={data as OAuthTokenInspectorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'webhookTester',
    title: 'Webhook Tester',
    subtitle: 'Ping webhook',
    category: 'Back End',
    icon: faWaveSquare,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <WebhookTesterTool.Component
        data={data as WebhookTesterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'cookieManager',
    title: 'Cookie Manager',
    subtitle: 'Edit cookies',
    category: 'Back End',
    icon: faGear,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    width: 420,
    height: 450,
    render: (data, onChange) => (
      <CookieManagerTool.Component
        data={data as CookieManagerData | undefined}
        onChange={onChange}
        onRefresh={handlers.refreshCookies}
      />
    )
  }
];
