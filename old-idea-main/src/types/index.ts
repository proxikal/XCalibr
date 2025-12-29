export interface Tool {
  id: string;
  name: string;
  description: string;
  icon: string;
  category: 'frontend' | 'backend' | 'other';
  onClick?: () => void;
}

export interface Settings {
  theme: 'dark' | 'light';
  notifications: boolean;
}

export type TabCategory = 'frontend' | 'backend' | 'other' | 'features';

export interface Feature {
  id: string;
  name: string;
  description: string;
  icon: string;
  enabled: boolean;
  category?: 'productivity' | 'development' | 'ui';
}

export interface ElementInfo {
  tagName: string;
  id: string | null;
  classes: string[];
  dimensions: {
    width: number;
    height: number;
    top: number;
    left: number;
  };
  styles: {
    color: string;
    backgroundColor: string;
    fontSize: string;
    fontFamily: string;
    padding: string;
    margin: string;
    border: string;
    zIndex: string;
  };
  attributes: Array<{
    name: string;
    value: string;
  }>;
}
