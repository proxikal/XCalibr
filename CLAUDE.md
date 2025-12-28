# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# ⚠️ TOP PRIORITY: UI Style & CSS Persistence ⚠️
- UI Directory holds the UI Style and Concept for future references
- MainUI.html is the main concept of the extension
- ToolUI.html has the examples for styling elements and how they should look.
- This UI and Style must be maintained through the entire project unless stated otherwise.

# ⚠️ TOP PRIORITY: STATE PERSISTENCE RULE ⚠️

**CRITICAL REQUIREMENT**: All application state MUST be persisted to survive crashes, browser restarts, and extension reloads. If the user clicks outside of the extension, when the user re-opens the extension it will open at is last state.

## State Persistence Requirements

When developing ANY new feature, tool, or code in this extension, you MUST:

1. **Use the Centralized Store**: Always use `src/stores/appStore.ts` for any state that needs to persist
   - DO NOT use plain `useState` for data that should survive crashes
   - Use `useAppStore`, `useActiveTab`, `useSettings`, or `useToolState` hooks
   - Create new store slices if needed, but ensure they're persisted

2. **Chrome Storage Integration**: All persistent state is automatically saved to `chrome.storage.local`
   - The store handles automatic debounced persistence
   - State is restored on extension reload/crash
   - Multi-context synchronization is built-in (popup, background, content scripts)

3. **Crash Recovery**: The app includes automatic crash detection
   - Heartbeat mechanism detects unexpected closures
   - Users are notified when recovering from crashes
   - Previous session state is fully restored

4. **Error Handling**: All components must handle errors gracefully
   - Wrap new features in error boundaries if they're critical
   - Log errors to storage for debugging (`xcalibr_error_logs`)
   - Provide recovery options in error UI

## Current Persistent State

The following state is currently persisted:
- **activeTab**: Current tab selection (frontend/backend/other)
- **settings**: User preferences (theme, notifications)
- **toolState**: Tool usage tracking (favorites, usage counts, last used)
- **sessionId**: Unique session identifier
- **lastActiveTimestamp**: Heartbeat for crash detection
- **crashRecoveryData**: Recovery information from previous crashes

## Adding New Persistent State

When adding new state that should persist:

```typescript
// ❌ WRONG - Will not survive crashes
const [myState, setMyState] = useState('value');

// ✅ CORRECT - Add to appStore.ts
export interface AppState {
  // ... existing state
  myNewFeature: {
    data: string;
    settings: MySettings;
  };
}

// Then use in components via hook
const [state, setState] = useAppStore();
const myData = state.myNewFeature.data;
```

## File References

- **Store**: `src/stores/appStore.ts` - Centralized persistent store
- **Hooks**: `src/hooks/useAppStore.ts` - React hooks for store access
- **Error Boundary**: `src/components/ErrorBoundary.tsx` - Crash recovery UI
- **Crash Recovery**: `src/components/CrashRecoveryNotification.tsx` - User notification

## Testing State Persistence

When implementing new features, test that:
1. State survives browser restart
2. State survives extension reload (chrome://extensions/)
3. State is restored after simulated crash (close popup during activity)
4. Multi-window state synchronization works
5. Error boundaries catch and recover from component errors

# Using Gemini CLI for Large Codebase Analysis

When analyzing large codebases or multiple files that might exceed context limits, use the Gemini CLI with its massive
context window. Use `gemini -p` to leverage Google Gemini's large context capacity.

## File and Directory Inclusion Syntax

Use the `@` syntax to include files and directories in your Gemini prompts. The paths should be relative to WHERE you run the
  gemini command:

### Examples:

**Single file analysis:**
gemini -p "@src/main.py Explain this file's purpose and structure"

Multiple files:
gemini -p "@package.json @src/index.js Analyze the dependencies used in the code"

Entire directory:
gemini -p "@src/ Summarize the architecture of this codebase"

Multiple directories:
gemini -p "@src/ @tests/ Analyze test coverage for the source code"

Current directory and subdirectories:
gemini -p "@./ Give me an overview of this entire project"

# Or use --all_files flag:
gemini --all_files -p "Analyze the project structure and dependencies"

# Implementation Verification Examples

Check if a feature is implemented:
gemini -p "@src/ @lib/ Has dark mode been implemented in this codebase? Show me the relevant files and functions"

Verify authentication implementation:
gemini -p "@src/ @middleware/ Is JWT authentication implemented? List all auth-related endpoints and middleware"

Check for specific patterns:
gemini -p "@src/ Are there any React hooks that handle WebSocket connections? List them with file paths"

Verify error handling:
gemini -p "@src/ @api/ Is proper error handling implemented for all API endpoints? Show examples of try-catch blocks"

Check for rate limiting:
gemini -p "@backend/ @middleware/ Is rate limiting implemented for the API? Show the implementation details"

Verify caching strategy:
gemini -p "@src/ @lib/ @services/ Is Redis caching implemented? List all cache-related functions and their usage"

Check for specific security measures:
gemini -p "@src/ @api/ Are SQL injection protections implemented? Show how user inputs are sanitized"

Verify test coverage for features:
gemini -p "@src/payment/ @tests/ Is the payment processing module fully tested? List all test cases"

# When to Use Gemini CLI

Use gemini -p when:
- Analyzing entire codebases or large directories
- Comparing multiple large files
- Need to understand project-wide patterns or architecture
- Current context window is insufficient for the task
- Working with files totaling more than 100KB
- Verifying if specific features, patterns, or security measures are implemented
- Checking for the presence of certain coding patterns across the entire codebase

# Important Notes

- Paths in @ syntax are relative to your current working directory when invoking gemini
- The CLI will include file contents directly in the context
- No need for --yolo flag for read-only analysis
- Gemini's context window can handle entire codebases that would overflow Claude's context
- When checking implementations, be specific about what you're looking for to get accurate results

## Project Brief Summary

**XCalibr** is a browser extension hub for developer tools. The extension provides a unified interface for common development utilities, organized into Front End, Back End, and Other categories.

## Design System

The UI follows these conventions:
- **Color palette**: Dark theme with primary accent `#00e600` (dev-green)
- **Background colors**: `#0f172a` (dev-dark), `#020617` (dev-darker), `#1e293b` (dev-card)
- **Dimensions**: Popup sized at 400px width × 600px height
- **Typography**: System UI font stack, antialiased
- **Component pattern**: Tool cards with icon, title, description, and hover states
- Each tool card transitions on hover with green accent glow effect

## Development Notes

When implementing new features:
- The HTML uses inline Tailwind configuration extending base theme with custom colors
- Tab switching will need JavaScript to manage visibility of different tool categories
- Each tool will likely need its own content script or panel implementation
- Tools that interact with page elements (Element Metadata Overlay, Color Picker, CSS Source Jump) will require content script injection
- Tools that are standalone utilities (JSON Formatter, Regex Tester) can run entirely in popup/panel context