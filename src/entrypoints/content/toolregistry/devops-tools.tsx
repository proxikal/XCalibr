import React from 'react';
import {
  faGear,
  faLock,
  faFileCode,
  faCode,
  faServer
} from '@fortawesome/free-solid-svg-icons';
import {
  CronGeneratorTool,
  ChmodCalculatorTool,
  DockerfileLinterTool,
  YamlValidatorTool,
  NginxConfigGeneratorTool,
  HtaccessGeneratorTool
} from '../Tools';
import type {
  CronGeneratorData,
  ChmodCalculatorData,
  DockerfileLinterData,
  YamlValidatorData,
  NginxConfigGeneratorData,
  HtaccessGeneratorData
} from '../Tools/tool-types';
import type { ToolRegistryEntry } from './types';

export const buildDevopsTools = (): ToolRegistryEntry[] => [
  {
    id: 'cronGenerator',
    title: 'Cron Generator',
    subtitle: 'Build cron expressions',
    category: 'DevOps',
    icon: faGear,
    hover: 'group-hover:border-yellow-500 group-hover:text-yellow-400',
    render: (data, onChange) => (
      <CronGeneratorTool.Component
        data={data as CronGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'chmodCalculator',
    title: 'Chmod Calculator',
    subtitle: 'File permissions',
    category: 'DevOps',
    icon: faLock,
    hover: 'group-hover:border-yellow-500 group-hover:text-yellow-400',
    render: (data, onChange) => (
      <ChmodCalculatorTool.Component
        data={data as ChmodCalculatorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'dockerfileLinter',
    title: 'Dockerfile Linter',
    subtitle: 'Check best practices',
    category: 'DevOps',
    icon: faFileCode,
    hover: 'group-hover:border-yellow-500 group-hover:text-yellow-400',
    height: 450,
    render: (data, onChange) => (
      <DockerfileLinterTool.Component
        data={data as DockerfileLinterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'yamlValidator',
    title: 'YAML Validator',
    subtitle: 'Validate syntax',
    category: 'DevOps',
    icon: faCode,
    hover: 'group-hover:border-yellow-500 group-hover:text-yellow-400',
    height: 450,
    render: (data, onChange) => (
      <YamlValidatorTool.Component
        data={data as YamlValidatorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'nginxConfigGenerator',
    title: 'Nginx Config Generator',
    subtitle: 'Server blocks',
    category: 'DevOps',
    icon: faServer,
    hover: 'group-hover:border-yellow-500 group-hover:text-yellow-400',
    height: 500,
    render: (data, onChange) => (
      <NginxConfigGeneratorTool.Component
        data={data as NginxConfigGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'htaccessGenerator',
    title: 'Htaccess Generator',
    subtitle: 'Apache rules',
    category: 'DevOps',
    icon: faFileCode,
    hover: 'group-hover:border-yellow-500 group-hover:text-yellow-400',
    height: 450,
    render: (data, onChange) => (
      <HtaccessGeneratorTool.Component
        data={data as HtaccessGeneratorData | undefined}
        onChange={onChange}
      />
    )
  }
];
