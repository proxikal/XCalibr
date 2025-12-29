# XCalibr Browser Extension

A unified developer tools hub for Chrome/Edge/Brave browsers built with **React + TypeScript**. XCalibr provides quick access to essential development utilities organized into Front End, Back End, and Other categories.

## Features

### Current Features (v1.0.2)
- ✅ **React 19** - Modern component-based architecture
- ✅ **TypeScript** - Full type safety throughout the codebase
- ✅ **Vite** - Lightning-fast build tool with HMR
- ✅ **Tailwind CSS v4** - Modern utility-first styling
- ✅ Modern dark-themed UI with #00e600 accent color
- ✅ Tab-based navigation (Front End / Back End / Other)
- ✅ Responsive popup interface (400x600px)
- ✅ Element inspector (toggle with right-click context menu)
- ✅ Keyboard shortcut support
- ✅ Chrome Storage integration with React hooks
- ✅ Custom hooks for Chrome APIs

## Tech Stack
- **Frontend:** React 19.2 + TypeScript 5.9
- **Build Tool:** Vite 7.3 with @crxjs/vite-plugin
- **Styling:** Tailwind CSS v4 with PostCSS
- **State Management:** Custom hooks + Chrome Storage API (Zustand ready)
- **Extension:** Manifest V3

## Installation

### For Development

1. **Install dependencies:**
   ```bash
   cd /Users/proxikal/Desktop/Dev/XCalibr
   npm install
   ```

2. **Build the extension:**
   ```bash
   npm run build
   ```

3. **Load the extension in Chrome/Edge/Brave:**
   - Open your browser and navigate to `chrome://extensions/`
   - Enable "Developer mode" (toggle in top-right corner)
   - Click "Load unpacked"
   - Select the `/Users/proxikal/Desktop/Dev/XCalibr/dist` folder
   - The XCalibr extension should now appear in your extensions list

4. **Pin the extension:**
   - Click the puzzle piece icon in your browser toolbar
   - Find "XCalibr" and click the pin icon
   - The XCalibr icon will now appear in your toolbar

## Development

### Available Scripts

```bash
# Start development server with HMR
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview

# Create distribution package (.zip)
npm run package

# Clean build artifacts
npm run clean
```

### Development Workflow

1. **Start development mode:**
   ```bash
   npm run dev
   ```

2. **Make changes** to files in `src/`

3. **Rebuild:**
   ```bash
   npm run build
   ```

4. **Reload extension** in `chrome://extensions/`
   - Click the refresh icon on the XCalibr extension card

## Usage

### Opening the Popup
- Click the XCalibr icon in your browser toolbar
- Use the keyboard shortcut (if configured)

### Navigating Tools
- Click on the **Front End**, **Back End**, or **Other** tabs to switch categories
- Click any tool card to activate it (currently shows "coming soon" notification)
- Last active tab is remembered between sessions (persisted in Chrome storage)

### Element Inspector
- Right-click on any webpage
- Select "Inspect with XCalibr" from the context menu
- Hover over elements to highlight them
- Click an element to select and view its details in the console

### Menu Options
- Click the hamburger menu (top-right) for:
  - Settings
  - Documentation (coming soon)
  - Support (coming soon)

## Project Structure

```
XCalibr/
├── src/                           # Source code (React + TypeScript)
│   ├── components/
│   │   ├── layout/
│   │   │   ├── Header.tsx        # App header with dropdown menu
│   │   │   ├── TabNavigation.tsx # Category tabs
│   │   │   └── Footer.tsx        # App footer
│   │   ├── ui/
│   │   │   └── ToolCard.tsx      # Reusable tool card component
│   │   └── tools/                # Tool-specific components (future)
│   ├── hooks/
│   │   ├── useStorage.ts         # Chrome storage sync hook
│   │   ├── useMessage.ts         # Chrome messaging hook
│   │   └── useActiveTab.ts       # Active tab tracker
│   ├── background/
│   │   └── service-worker.ts     # Background service worker
│   ├── content/
│   │   └── content-script.ts     # Content script for page interaction
│   ├── popup/
│   │   ├── index.html            # Popup entry HTML
│   │   └── main.tsx              # React entry point
│   ├── data/
│   │   └── tools.ts              # Tool definitions
│   ├── types/
│   │   └── index.ts              # TypeScript type definitions
│   ├── styles/
│   │   └── index.css             # Tailwind directives & global styles
│   ├── App.tsx                   # Main App component
│   └── manifest.json             # Extension manifest (MV3)
├── public/
│   └── icons/                    # Extension icons (16, 32, 48, 128)
├── dist/                         # Built extension (generated)
├── vite.config.ts                # Vite configuration
├── tsconfig.json                 # TypeScript configuration
├── tsconfig.node.json            # TypeScript Node configuration
├── tailwind.config.js            # Tailwind CSS configuration
├── postcss.config.js             # PostCSS configuration
├── package.json                  # Dependencies and scripts
├── .gitignore                    # Git ignore rules
├── README.md                     # This file
└── CLAUDE.md                     # Development guidance for Claude Code
```

## Custom Hooks

### `useStorage<T>(key: string, initialValue: T)`
Syncs React state with `chrome.storage.local`:
```typescript
const [activeTab, setActiveTab] = useStorage<TabCategory>('activeTab', 'frontend');
```

### `useMessage(handler)`
Listen for Chrome runtime messages:
```typescript
useMessage((message, sender) => {
  console.log('Received:', message);
});
```

### `useActiveTab()`
Get the currently active browser tab:
```typescript
const { activeTab, loading } = useActiveActiveTab();
```

## Building New Tools

When adding a new tool:

1. **Add tool definition** to `src/data/tools.ts`
2. **Create tool component** in `src/components/tools/`
3. **Update tool card handler** in `src/App.tsx`
4. **Add content script logic** if tool needs page interaction
5. **Add message handlers** in `src/background/service-worker.ts` if needed
6. **Update types** in `src/types/index.ts`

## Browser Compatibility

- ✅ Google Chrome (v88+)
- ✅ Microsoft Edge (v88+)
- ✅ Brave Browser
- ⚠️ Firefox (requires manifest conversion for full compatibility)
- ❌ Safari (different extension format required)

## Permissions

The extension requests the following permissions:

- **storage**: Save user preferences and settings
- **activeTab**: Access the currently active tab for tools
- **contextMenus**: Add right-click menu options
- **host_permissions (all_urls)**: Allow tools to work on any website

## Troubleshooting

### Extension won't load
- Ensure you built the extension: `npm run build`
- Ensure Developer mode is enabled in `chrome://extensions/`
- Load the `dist/` folder, not the root folder
- Check the browser console for errors

### Build fails
- Delete `node_modules` and run `npm install` again
- Check Node.js version (requires >= 14.0.0)
- Check for TypeScript errors: `npm run build`

### Changes not reflecting
- Rebuild: `npm run build`
- Click refresh icon in `chrome://extensions/`
- Hard reload the extension popup (Ctrl+R or Cmd+R)

### Hot Module Replacement (HMR) not working
- Ensure you're running `npm run dev`
- Load the `dist/` folder in the browser
- Check Vite console for errors


## License

Currently unlicensed personal project.

## Version History

### v1.0.2 (Current)
- ✅ Full React + TypeScript conversion
- ✅ Vite build system with HMR
- ✅ Custom Chrome API hooks
- ✅ Component-based architecture
- ✅ Tailwind CSS v4 integration
- ✅ Type-safe development experience
- ✅ Optimized production builds
- ✅ Service worker and content script in TypeScript
