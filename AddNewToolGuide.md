# XCalibr Project Guide & Workflow

## Overview

Each tool in XCalibr follows a consistent pattern:
1. **Tool Component** - React component with data/onChange props
2. **Tool Class** - Wrapper class with static Component property
3. **Tool Types** - TypeScript interface for tool data
4. **Tool Registration** - Entry in the tool registry
5. **Menu Entry** - Entry in the menu system
6. **Tests** - Unit and integration tests

**Role:** You are an expert Software Engineer and QA specialist working on the XCalibr Chrome Extension.
**Context:** XCalibr is a developer utility extension built with **WXT (Web Extension Tools)**, **React**, **TypeScript**, and **Tailwind CSS**.

### Key Points:
- Component receives `data` (current state) and `onChange` (state updater)
- Always provide default values: `data?.field ?? defaultValue`
- Use `onChange({ ...data, field: newValue })` to update state
- All data persists automatically via Chrome storage
- The tool must have complete state persistence across all tabs.

## Core Mandates & Rules

1.  **Test-First Architecture (TDD):**
    *   You **MUST** create or update the test file `src/entrypoints/__tests__/tools/<tool-name>.test.ts` **BEFORE** implementing the tool logic.
    *   Tests drive the implementation. If the test doesn't fail first, you aren't doing it right.
    *   Use `aiAssertTruthy` for robust assertions.

2.  **Strict Typing:**
    *   All new tools must define their state interface in `src/entrypoints/content/Tools/tool-types.ts`.
    *   No `any` types. Use proper interfaces and types.
    *   Run `npm run typecheck` to verify data integrity.

3.  **Styling & UI:**
    *   Use **Tailwind CSS** for all styling.
    *   **Theme:** Dark mode by default (`bg-[#1a1a2e]`, text `gray-300`/`white`, borders `gray-700`).
    *   **Icons:** Use FontAwesome (`@fortawesome/free-solid-svg-icons`).
    *   Components must be responsive and compact.

4.  **Filesystem & Structure:**
    *   **Tools:** `src/entrypoints/content/Tools/`
    *   **Registry:** `src/entrypoints/content/toolregistry/`
    *   **Tests:** `src/entrypoints/__tests__/tools/`

## Development Workflow

Follow this cycle for every new feature or tool.

### Phase 1: Preparation & Testing (The "Red" Phase)

1.  **Define Requirements:** Understand what the tool needs to do.
2.  **Create Test File:**
    *   Create `src/entrypoints/__tests__/tools/<tool-kebab-case>.test.ts`.
    *   Import `mountWithTool` and `resetChrome`.
    *   Write tests for: Rendering, Input existence, and Output verification.
    *   *Example:*
        ```typescript
        describe('My Tool', () => {
          it('renders correctly', async () => {
            const root = await mountWithTool('myToolId');
            aiAssertTruthy({ name: 'ToolRendered' }, root);
          });
        });
        ```

### Phase 2: Definition & Implementation (The "Green" Phase)

3.  **Define Types:**
    *   Edit `src/entrypoints/content/Tools/tool-types.ts`.
    *   Export a specific type `MyToolData` describing the tool's persistent state.

4.  **Implement Component:**
    *   Create `src/entrypoints/content/Tools/MyTool.tsx`.
    *   Implement the UI using Tailwind.
    *   **CRITICAL:** Export the static class wrapper:
        ```typescript
        export class MyTool {
          static Component = MyToolComponent;
        }
        ```

5.  **Register Tool:**
    *   Identify the correct category in `src/entrypoints/content/toolregistry/` (e.g., `devops-tools.tsx`, `webdev-tools.tsx`).
    *   Add the configuration object (ID, Title, Icon, Render function).
    *   **Note:** The `id` here MUST match the ID used in your test.

### Phase 3: Verification (The "Refactor" Phase)

6.  **Run Tests:**
    *   Execute `npx vitest src/entrypoints/__tests__/tools/<tool-kebab-case>.test.ts`.
    *   Ensure all tests pass.

7.  **Type Check:**
    *   Execute `npm run typecheck`.

## Commands Reference

| Command | Description |
| :--- | :--- |
| `npm run dev` | Start development server (HMR). |
| `npm run build` | Build the extension for production. |
| `npm test` | Run all tests (Vitest). |
| `npx vitest <path>` | Run a specific test file. |
| `npm run typecheck` | Run TypeScript type checking. |

---

## Tool Creation Checklist

Use this checklist to ensure no step is missed.

| Step | Action | File Path / Pattern |
| :--- | :--- | :--- |
| **01** | **Create Test** | `src/entrypoints/__tests__/tools/<tool-name>.test.ts` |
| **02** | **Define Types** | `src/entrypoints/content/Tools/tool-types.ts` |
| **03** | **Create Component** | `src/entrypoints/content/Tools/<ToolName>Tool.tsx` |
| **04** | **Register Tool** | `src/entrypoints/content/toolregistry/<category>-tools.tsx` |
| **05** | **Verify Tests** | `npx vitest <tool-name>` |
| **06** | **Verify Types** | `npm run typecheck` |