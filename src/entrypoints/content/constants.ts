import {
  faBolt,
  faCode,
  faDatabase,
  faFile,
  faFileLines,
  faPuzzlePiece,
  faShieldHalved,
  faSpider
} from '@fortawesome/free-solid-svg-icons';
import type { IconDefinition } from '@fortawesome/fontawesome-svg-core';

export const ROOT_ID = 'xcalibr-root';
export const MENU_HEIGHT = 550;
export const MENU_BAR_HEIGHT = 32;
export const QUICK_BAR_PAGE_SIZE = 6;
export const ICON_SIZE_CLASS = 'w-3 h-3';

export const MENU_ICONS: Record<string, IconDefinition> = {
  'File': faFile,
  'Web Dev': faCode,
  'Database': faDatabase,
  'CyberSec': faShieldHalved,
  'Extension Dev': faPuzzlePiece,
  'Data & Text': faFileLines,
  'Scraper': faSpider
};

export const CATEGORY_BADGE_CLASSES: Record<string, string> = {
  'Web Dev': 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30',
  'Front End': 'bg-blue-500/10 text-blue-300 border-blue-500/30',
  'Back End': 'bg-amber-500/10 text-amber-300 border-amber-500/30',
  'CyberSec': 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
  'default': 'bg-slate-500/10 text-slate-300 border-slate-500/30'
};

export const getCategoryBadge = (category: string): string => {
  return CATEGORY_BADGE_CLASSES[category] ?? CATEGORY_BADGE_CLASSES['default'];
};
