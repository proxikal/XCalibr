# XCalibr Rules (AI-Strict)

## Purpose
This file is the single source of truth for adding new features or tools.

## Required Workflow (Always Follow)
1. **Plan tests first (Vitest).**
   - Write the test cases before code changes.
   - Cover happy path + edge cases + persistence.
2. **Implement the feature/tool.**
   - Keep logic outside UI components when possible.
3. **Verify tests.**
   - Run `npm test -- --run` and fix failures.
4. **Build.**
   - Run `npm run build` and confirm no errors.

## Non-Negotiable Standards
- **UI Consistency:** Use the existing extension UI design system.
- **UI Persistence:** New UI must follow `ExtensionUI.html` layout and styling.
- **State Persistence:** All inputs/settings/results must persist across tabs and restarts using the existing state store.
- **Tool Registry:** Every new tool must be registered in the Tool Registry.
- **Tool Class System:** Every tool must be a class with a static `Component` in `src/entrypoints/content/Tools/`.

## Adding a New Tool (Step-by-Step)
1. **Create tool class file.**
   - Path: `src/entrypoints/content/Tools/<ToolName>Tool.tsx`
   - Export `class <ToolName>Tool { static Component = <ToolName>ToolComponent; }`
2. **Add tool data type (if needed).**
   - Path: `src/entrypoints/content/Tools/tool-types.ts`
3. **Register tool.**
   - Add to `src/entrypoints/content/tool-registry.tsx`.
   - Provide `id`, `title`, `subtitle`, `category`, `icon`, `hover`, and `render`.
4. **Add menu item.**
   - Update `src/entrypoints/content/menu.ts` to include the tool in the correct menu/submenu.
5. **Wire state persistence.**
   - Use the existing state store so data persists across tabs and restarts.
6. **Add/Update tests.**
   - Extend `src/entrypoints/__tests__/content.test.tsx` (or add a new test file).

## Adding a New Feature (Non-Tool)
1. **Locate the correct module** (`content.tsx` or relevant shared module).
2. **Add tests first**, then implement.
3. **Persist state** if the feature has inputs/settings.
4. **Build + test** as above.

## Quick Checklist (Before You Finish)
- [ ] Tests written first (Vitest).
- [ ] State persists across tabs + restarts.
- [ ] UI matches `ExtensionUI.html` patterns.
- [ ] Tool class + registry + menu updated (if tool).
- [ ] `npm test -- --run` passes.
- [ ] `npm run build` passes.
