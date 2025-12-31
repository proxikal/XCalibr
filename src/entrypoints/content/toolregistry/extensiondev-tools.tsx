import React from 'react';
import { faPuzzlePiece, faKey, faLanguage } from '@fortawesome/free-solid-svg-icons';
import {
  ManifestValidatorTool,
  PermissionsReferenceTool,
  I18nHelperTool
} from '../Tools';
import type {
  ManifestValidatorData,
  PermissionsReferenceData,
  I18nHelperData
} from '../Tools/tool-types';
import type { ToolRegistryEntry } from './types';

export const buildExtensionDevTools = (): ToolRegistryEntry[] => [
  {
    id: 'manifestValidator',
    title: 'Manifest V3 Validator',
    subtitle: 'Validate manifest',
    category: 'Extension Dev',
    icon: faPuzzlePiece,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    width: 400,
    render: (data, onChange) => (
      <ManifestValidatorTool.Component
        data={data as ManifestValidatorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'permissionsReference',
    title: 'Permissions Reference',
    subtitle: 'Chrome permissions',
    category: 'Extension Dev',
    icon: faKey,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <PermissionsReferenceTool.Component
        data={data as PermissionsReferenceData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'i18nHelper',
    title: 'i18n Message Helper',
    subtitle: 'Localization helper',
    category: 'Extension Dev',
    icon: faLanguage,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <I18nHelperTool.Component
        data={data as I18nHelperData | undefined}
        onChange={onChange}
      />
    )
  }
];
