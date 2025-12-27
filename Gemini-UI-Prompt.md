Design a **modern, dark-themed UI** for a **developer-focused browser extension** using the **latest version of Tailwind CSS** (utility-first, no deprecated classes).

### Overall Goal

This extension will act as a **hub for multiple developer tools** used in everyday workflows. The UI should feel **fast, minimal, and professional**, optimized for a **browser extension popup** (compact but scalable).

### Color & Theme

* Primary accent color: **#00e600** (use for highlights, active states, icons, and subtle accents — not overwhelming)
* Dark background with strong contrast
* Clean typography suitable for long sessions

### Layout Structure

1. **Top Banner**

   * Fixed header
   * Extension name or logo placeholder
   * Subtle use of #00e600 for branding or underline
2. **Content Section (Dynamic)**

   * Designed to render a dynamic list of tools
   * Each tool item should include:

     * An icon (placeholder SVG or Heroicon-style icon)
     * Tool name
     * Hover and active states
   * Card or list-based layout that scales well as tools increase
3. **Category / Tab System**

   * Tabs at the top of the content section
   * Categories:

     * Front End
     * Back End
     * Other
   * Active tab clearly highlighted using #00e600
   * Smooth transitions between tabs (CSS only)
4. **Footer**

   * Minimal footer
   * Could include version text or a settings icon placeholder

### Placeholder Data

Include several placeholder tools for visual testing, for example:

* Front End:
  * Component Inspector
  * CSS Debugger
* Back End:
  * API Tester
  * JSON Formatter
* Other:
  * Regex Tester
  * Color Picker

### Technical Notes

* Use semantic HTML
* Tailwind CSS only (no external CSS frameworks)
* Design should be responsive within a browser extension popup
* Assume JavaScript will later handle state, tabs, and dynamic data

### Output Expectations

* Provide a complete HTML + Tailwind layout
* Clean, readable class structure
* UI-first focus (no JS logic required)
* Modern, developer-tool aesthetic

The final result should feel like a polished internal tool a professional developer would use daily.
