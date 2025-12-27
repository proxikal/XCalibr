# Extension Idea
This app will help me with tools for basic development etc.
It's basically a hub for all of my tools to make my life easier.

# Strong “Core Feature” Ideas
If you want this extension to stand out:
- Unified DevTools Panel combining multiple features
- State + Network + Storage snapshotting
- One-click “debug mode” for any site
- Dev environment time-saver metrics (what saved you time today)

# Common Ideas
- Website Change Notifier: Alerts you when a page’s content changes.
- Clean Reading Mode: Strips clutter and ads, keeps only content.
- Link Preview on Hover: Preview links without opening a new tab.
- Auto Dark Mode per Site : Custom dark/light mode settings per website.
- URL Notes: Attach personal notes to specific URLs.
- Color Picker: Catch whatever color the mouse is hovering over in hex (#000000) and RGB.

# Extension Permission Auditor
Show exactly:
- which APIs you’re using
- which permissions are unused
Helps keep manifests clean

# Extension Manifest Validator++
Validates:
- MV3 rules
- CSP issues
- background/service worker lifecycles
Warns before Chrome does

# Extension Message Passing Tracer
Visualize messages between:
content scripts
background service workers
popup / options
Debug async bugs easily


# Element Metadata Overlay
Hover an element → see:
- computed font stack
- color contrast ratio
- box model (margin/padding) as numbers
- z-index & stacking context
Faster than digging through DevTools panels.
Make this feature so it can be toggled on and off with a keyboatf shortcut.

# CSS Source Jump
Click an element → jump directly to the CSS file & line that defines it (even across bundled files if sourcemaps exist).

# Live CSS Scratchpad
- Temporary CSS injected into the page
- Persists per domain
- Toggle on/off quickly
Great for testing fixes before touching code

# DOM Diff Tool
Snapshot DOM → perform action → diff changes
Extremely useful for debugging JS-heavy apps.

# Design Token Inspector
Extract CSS variables, colors, spacing scale, fonts
Export as JSON / Tailwind config / CSS variables

# Responsive Breakpoint Tester
Preset viewport buttons
Side-by-side viewports
Scroll-synced
Much faster than resizing manually

# Visual Grid & Baseline Overlay
Toggle grid overlay (8px, 4px, custom)
Helpful when implementing designs

# Contrast & Accessibility Live Checker
Hover text → WCAG score
Flags issues instantly (no Lighthouse run needed)

