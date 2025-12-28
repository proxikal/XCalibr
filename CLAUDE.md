# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# VERY IMPORTANT
- UI Directory holds the UI Style and Concept for future references
- MainUI.html is the main concept of the extension
- ToolUI.html is the main concept for any tools that will be added.

- This UI and Style must be maintained through the entire project unless stated otherwise.


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

## Project Overview

**XCalibr** is a browser extension hub for developer tools. The extension provides a unified interface for common development utilities, organized into Front End, Back End, and Other categories.

## Current State

This is an early-stage project. Currently implemented:
- UI prototype (`extension_ui.html`) using Tailwind CSS via CDN
- Dark theme with `#00e600` accent color
- Tab-based navigation system (Front End / Back End / Other)
- Placeholder tools for visual reference

**Not yet implemented:**
- Browser extension manifest (manifest.json)
- Background service workers or content scripts
- Actual tool functionality
- Build/bundling system

## Design System

The UI follows these conventions:
- **Color palette**: Dark theme with primary accent `#00e600` (dev-green)
- **Background colors**: `#0f172a` (dev-dark), `#020617` (dev-darker), `#1e293b` (dev-card)
- **Dimensions**: Popup sized at 400px width × 600px height
- **Typography**: System UI font stack, antialiased
- **Component pattern**: Tool cards with icon, title, description, and hover states
- Each tool card transitions on hover with green accent glow effect

## Planned Features

Reference `# Extension Ideas.md` for the full feature roadmap. Key planned tools include:

**Front End Tools:**
- Component Inspector (React/Vue analysis)
- CSS Debugger (live styling playground)
- Element Metadata Overlay (hover to see font, colors, box model, z-index)
- CSS Source Jump
- Live CSS Scratchpad
- DOM Diff Tool
- Design Token Inspector

**Back End Tools:**
- API Tester
- JSON Formatter

**Other Tools:**
- Regex Tester
- Color Picker (extract colors in hex/RGB on hover)
- Extension Permission Auditor
- Extension Manifest Validator
- Extension Message Passing Tracer

## Development Notes

When implementing new features:
- The HTML uses inline Tailwind configuration extending base theme with custom colors
- Tab switching will need JavaScript to manage visibility of different tool categories
- Each tool will likely need its own content script or panel implementation
- Tools that interact with page elements (Element Metadata Overlay, Color Picker, CSS Source Jump) will require content script injection
- Tools that are standalone utilities (JSON Formatter, Regex Tester) can run entirely in popup/panel context

## Architecture Considerations

When building out the extension:
- Decide on Manifest V3 vs V2 (prefer V3 for future compatibility)
- Determine which tools need host permissions and which can run sandboxed
- Plan message passing architecture between popup, background worker, and content scripts
- Consider state management for tool preferences and per-domain settings
- Some features (Live CSS Scratchpad, URL Notes) need persistent storage strategy
