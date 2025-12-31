import React from 'react';
import {
  faComment,
  faEyeSlash,
  faCloud,
  faCodeBranch,
  faExternalLinkAlt,
  faKey,
  faFileAlt
} from '@fortawesome/free-solid-svg-icons';
import {
  CommentSecretScraperTool,
  HiddenFieldRevealerTool,
  S3BucketFinderTool,
  GitExposureCheckerTool,
  TargetBlankAuditorTool,
  StorageSecretHunterTool,
  MetafileScannerTool
} from '../Tools';
import type {
  CommentSecretScraperData,
  HiddenFieldRevealerData,
  S3BucketFinderData,
  GitExposureCheckerData,
  TargetBlankAuditorData,
  StorageSecretHunterData,
  MetafileScannerData
} from '../Tools/tool-types';
import type { ToolRegistryEntry } from './types';

export const buildRedteamBatchATools = (): ToolRegistryEntry[] => [
  {
    id: 'commentSecretScraper',
    title: 'Comment & Secret Scraper',
    subtitle: 'Find secrets in source',
    category: 'Red Team',
    icon: faComment,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 450,
    height: 550,
    render: (data, onChange) => (
      <CommentSecretScraperTool.Component
        data={data as CommentSecretScraperData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'hiddenFieldRevealer',
    title: 'Hidden Field Revealer',
    subtitle: 'Expose hidden inputs',
    category: 'Red Team',
    icon: faEyeSlash,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 450,
    height: 500,
    render: (data, onChange) => (
      <HiddenFieldRevealerTool.Component
        data={data as HiddenFieldRevealerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 's3BucketFinder',
    title: 'S3 Bucket Finder',
    subtitle: 'Find AWS S3 URLs',
    category: 'Red Team',
    icon: faCloud,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 450,
    height: 480,
    render: (data, onChange) => (
      <S3BucketFinderTool.Component
        data={data as S3BucketFinderData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'gitExposureChecker',
    title: 'Git Exposure Checker',
    subtitle: 'Check for .git exposure',
    category: 'Red Team',
    icon: faCodeBranch,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 420,
    height: 520,
    render: (data, onChange) => (
      <GitExposureCheckerTool.Component
        data={data as GitExposureCheckerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'targetBlankAuditor',
    title: 'Target Blank Auditor',
    subtitle: 'Find tabnabbing vulns',
    category: 'Red Team',
    icon: faExternalLinkAlt,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 480,
    height: 550,
    render: (data, onChange) => (
      <TargetBlankAuditorTool.Component
        data={data as TargetBlankAuditorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'storageSecretHunter',
    title: 'Storage Secret Hunter',
    subtitle: 'Scan storage for secrets',
    category: 'Red Team',
    icon: faKey,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 520,
    height: 650,
    render: (data, onChange) => (
      <StorageSecretHunterTool.Component
        data={data as StorageSecretHunterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'metafileScanner',
    title: 'Metafile Scanner',
    subtitle: 'Check for exposed metafiles',
    category: 'Red Team',
    icon: faFileAlt,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 450,
    height: 550,
    render: (data, onChange) => (
      <MetafileScannerTool.Component
        data={data as MetafileScannerData | undefined}
        onChange={onChange}
      />
    )
  }
];
