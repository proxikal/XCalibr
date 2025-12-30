# Tool Development Guide

This guide provides step-by-step instructions for building a new tool in XCalibr.

## Overview

Each tool in XCalibr follows a consistent pattern:
1. **Tool Component** - React component with data/onChange props
2. **Tool Class** - Wrapper class with static Component property
3. **Tool Types** - TypeScript interface for tool data
4. **Tool Registration** - Entry in the tool registry
5. **Menu Entry** - Entry in the menu system
6. **Tests** - Unit and integration tests

---

## Step 1: Create the Tool Component File

**Location:** `src/entrypoints/content/Tools/<ToolName>Tool.tsx`

### Basic Template:

```tsx
import React from 'react';
import type { <ToolName>Data } from './tool-types';

const <ToolName>ToolComponent = ({
  data,
  onChange
}: {
  data: <ToolName>Data | undefined;
  onChange: (next: <ToolName>Data) => void;
}) => {
  // Extract values with defaults
  const someValue = data?.someValue ?? '';
  const output = data?.output ?? '';

  // Handler functions
  const handleAction = () => {
    // Process data
    const result = '...';
    onChange({ ...data, output: result });
  };

  return (
    <div className="space-y-3">
      {/* Tool title */}
      <div className="text-xs text-slate-200">Tool Name</div>

      {/* Input field */}
      <input
        type="text"
        value={someValue}
        onChange={(e) => onChange({ ...data, someValue: e.target.value })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Enter value..."
      />

      {/* Action button */}
      <button
        type="button"
        onClick={handleAction}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
      >
        Run Action
      </button>

      {/* Output area */}
      <textarea
        value={output}
        readOnly
        rows={5}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Output will appear here..."
      />
    </div>
  );
};

export class <ToolName>Tool {
  static Component = <ToolName>ToolComponent;
}
```

### Key Points:
- Component receives `data` (current state) and `onChange` (state updater)
- Always provide default values: `data?.field ?? defaultValue`
- Use `onChange({ ...data, field: newValue })` to update state
- All data persists automatically via Chrome storage

---

## Step 2: Add Tool Data Type

**Location:** `src/entrypoints/content/Tools/tool-types.ts`

Add your tool's data interface:

```typescript
export interface <ToolName>Data {
  input?: string;
  output?: string;
  error?: string;
  // Add other fields as needed
}
```

### Common Field Patterns:
- `input` / `output` - For transformation tools
- `error` - For error messages
- `isActive` - For toggle/picker tools
- `history` - For tools that track history
- `entries` - For list-based tools

---

## Step 3: Register the Tool

**Location:** `src/entrypoints/content/tool-registry.tsx`

### 3a. Import the Tool Class:

```typescript
import { <ToolName>Tool } from './Tools/<ToolName>Tool';
```

### 3b. Add to TOOLS Array:

```typescript
export const TOOLS: ToolEntry[] = [
  // ... existing tools
  {
    id: '<toolId>',              // camelCase, unique identifier
    title: 'Tool Display Name',   // Shown in UI
    subtitle: 'Brief description', // Shown under title
    category: 'category-name',    // For grouping (see categories below)
    icon: IconComponent,          // Lucide React icon
    hover: 'Tooltip text',        // Shown on hover
    render: (data, onChange) => (
      <<ToolName>Tool.Component data={data} onChange={onChange} />
    )
  },
];
```

### Categories:
- `webdev` - Web development tools
- `json` - JSON tools
- `sql` - SQL tools
- `nosql` - NoSQL/database tools
- `security` - Security/testing tools
- `frontend` - Frontend/CSS tools
- `backend` - Backend/API tools

---

## Step 4: Add Menu Entry

**Location:** `src/entrypoints/content/menu.ts`

Find the appropriate menu section and add your tool:

```typescript
export const MENU_ITEMS: MenuItem[] = [
  {
    label: 'Category Name',
    submenu: [
      // ... existing items
      { label: 'Tool Display Name', toolId: '<toolId>' },
    ]
  },
];
```

### Menu Structure:
- **File** - Help, Settings
- **Web Dev** - Code Injector, Debugger, Storage Explorer, etc.
- **Database** - JSON tools, SQL tools, NoSQL tools
- **CyberSec** - Recon, Testing, Network tools

---

## Step 5: Create Tests

**Location:** `src/entrypoints/content/Tools/__tests__/<ToolName>Tool.test.tsx`

### Test Template:

```tsx
import { beforeEach, describe, it } from 'vitest';
import { aiAssertEqual, aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitFor,
  findButtonByText,
  waitForState,
  typeInput
} from '../../../__tests__/integration-test-utils';

describe('<ToolName>Tool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('performs main action', async () => {
      // Mount tool with initial data
      const root = await mountWithTool('<toolId>', {
        input: 'test input',
        output: ''
      });
      if (!root) return;

      // Find and click action button
      const button = await waitFor(() => findButtonByText(root, 'Run Action'));
      aiAssertTruthy({ name: '<ToolName>ActionButton' }, button);
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();

      // Verify state was updated
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return (toolData.<toolId>?.output ?? '').includes('expected');
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.<toolId>?.output ?? '';
      aiAssertIncludes({ name: '<ToolName>Output' }, output, 'expected');
    });
  });
});
```

### Test Utilities:
- `mountWithTool(toolId, initialData)` - Mount tool with state
- `findButtonByText(root, text)` - Find button by label
- `typeInput(input, value)` - Type into input/textarea
- `waitFor(getter)` - Wait for element to appear
- `waitForState(predicate)` - Wait for state condition
- `flushPromises()` - Wait for async operations

### Assertion Functions:
- `aiAssertTruthy(context, value)` - Assert value is truthy
- `aiAssertEqual(context, actual, expected)` - Assert equality
- `aiAssertIncludes(context, string, substring)` - Assert string contains

---

## Step 6: Verify Implementation

Run the following commands:

```bash
# Type check
npm run typecheck

# Run tests
npm test -- --run

# Build
npm run build
```

---

## Common Patterns

### Chrome Runtime Messages (for background script communication):

```tsx
// In component
const handleFetch = async () => {
  const response = await chrome.runtime.sendMessage({
    type: 'xcalibr-your-action',
    payload: { url: '...' }
  });
  onChange({ ...data, output: response.body });
};
```

```typescript
// In background.ts - add handler
case 'xcalibr-your-action': {
  const result = await fetch(payload.url);
  return { body: await result.text() };
}
```

### Toggle/Picker Tools:

```tsx
const isActive = data?.isActive ?? false;

const handleToggle = () => {
  onChange({ ...data, isActive: !isActive });
};

useEffect(() => {
  if (!isActive) return;

  const handleClick = (e: MouseEvent) => {
    // Capture element
    onChange({ ...data, isActive: false, captured: e.target });
  };

  document.addEventListener('click', handleClick);
  return () => document.removeEventListener('click', handleClick);
}, [isActive]);
```

### Copy to Clipboard:

```tsx
<button onClick={() => navigator.clipboard.writeText(output)}>
  Copy
</button>
```

### Error Handling:

```tsx
const handleAction = () => {
  try {
    const result = riskyOperation();
    onChange({ ...data, output: result, error: '' });
  } catch (err) {
    onChange({ ...data, error: err instanceof Error ? err.message : 'Unknown error' });
  }
};

{data?.error && (
  <div className="text-red-400 text-xs">{data.error}</div>
)}
```

---

## UI Component Classes

### Standard Input:
```
w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500
```

### Standard Button:
```
w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors
```

### Primary Button:
```
w-full rounded bg-blue-600 px-2 py-1.5 text-xs text-white hover:bg-blue-500 transition-colors
```

### Active Toggle Button:
```
w-full rounded px-2 py-1.5 text-xs border transition-colors bg-blue-500/10 border-blue-500/40 text-blue-200
```

### Output Textarea:
```
w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono
```

### Error Text:
```
text-red-400 text-xs
```

### Section Label:
```
text-xs text-slate-200
```

### Help Text:
```
text-[11px] text-slate-500
```

---

## Checklist

- [ ] Created `<ToolName>Tool.tsx` with component and class
- [ ] Added data type to `tool-types.ts`
- [ ] Imported and registered in `tool-registry.tsx`
- [ ] Added menu entry in `menu.ts`
- [ ] Created test file with integration tests
- [ ] Ran `npm run typecheck` (passes)
- [ ] Ran `npm test -- --run` (passes)
- [ ] Ran `npm run build` (passes)
