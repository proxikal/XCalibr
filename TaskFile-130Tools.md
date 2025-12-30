

# Role and Objective
- You are an expert MV3 Browser Extension Developer.
- You are a Senior SDET and React 18 Specialist.
- You are a Senior TypeScript and WXT Developer.
- You are a Senior Tailwind CSS Developer
- You are tasked with expanding an existing Manifest V3 (MV3) browser extension.
- You will be creating new tools and features to implement into an existing architecture.
- You will need to maintain a STRICT Policy of following CLAUDE.md and make sure you reference it frequently.
- Each tool and feature needs to be fully functional and you need to follow the strict rules laid out.


# Objective
- We will be writing a LARGE amount of tools today, we need to make sure that code structure and integrity is key
- We cannot stray from the current projects architecture and CLAUDE.md must be frequently referenced to refresh memory.
- We will be setting up strict unit tests as directed by the tasks below.

# Workflow Required
- Make sure to follow the required Workflow when implementing or changing new features in tools.
- TEST, TEST and TEST! If the test fails, go back to fix the code and test again until it's fixed.


# New Tool Ideas for XCalibr

This document outlines 100 new tool ideas to expand the XCalibr suite, categorized by domain. These tools are designed to be compatible with Chrome MV3 architecture (client-side execution, storage usage, API fetchers).

## **REQUIRED:**
You must follow CLAUDE.md STRICTLY while building these tools and their tests.
You must consistently reference CLAUDE.md to keep the structure and rules intact.


## Category: OSINT (Open Source Intelligence)
*Tools for gathering publicly available information.*

1. **Whois Lookup**
   - **Function:** Fetches WHOIS data for a given domain using a public API (e.g., RDAP). Displays registrar, dates, and nameservers.
   - **Tests:** Mock API response, verify data parsing and display fields.

2. **DNS Record Viewer**
   - **Function:** Queries standard DNS records (A, AAAA, MX, TXT, CNAME, NS) for a domain via DNS-over-HTTPS (DoH) providers like Google or Cloudflare.
   - **Tests:** Mock DoH fetch, verify record types are correctly categorized.

3. **Reverse IP Lookup**
   - **Function:** Checks which domains are hosted on a specific IP address using a passive DNS API.
   - **Tests:** Mock API, test list rendering of domains.

4. **Username Search (Sherlock-lite)**
   - **Function:** Checks the existence of a username across popular social media platforms by verifying profile URL responses (status 200 vs 404).
   - **Tests:** Mock fetch requests for various platforms, verify status determination logic.

5. **Exif Metadata Viewer**
   - **Function:** Extracts EXIF/IPTC/XMP metadata from local image files or URLs. Displays camera model, GPS (with map link), and timestamps.
   - **Tests:** Load sample images with known metadata, assert extracted values match.

6. **Email Breach Checker**
   - **Function:** Queries HIBP (Have I Been Pwned) API (requires key or alternative public breach APIs) to check if an email was involved in known breaches.
   - **Tests:** Mock API response (pwned vs safe), verify alert UI states.

7. **SSL Certificate Decoder**
   - **Function:** Fetches and parses the SSL certificate chain for a domain. Shows validity dates, issuer, subject, and SANs.
   - **Tests:** Mock cert chain data, verify date formatting and issuer parsing.

8. **Google Dork Generator**
   - **Function:** UI builder for advanced Google search queries (inurl:, intitle:, filetype:). Helps users construct complex dorks for finding specific files or vulnerabilities.
   - **Tests:** Verify string concatenation logic based on selected filters and inputs.

9. **Subdomain Finder (Passive)**
   - **Function:** Uses Certificate Transparency (CT) logs API to find subdomains for a target domain.
   - **Tests:** Mock CT log API response, verify deduplication of subdomains.

10. **Wayback Machine Viewer**
    - **Function:** Checks Internet Archive availability for a URL and provides a calendar view of snapshots.
    - **Tests:** Mock Wayback CDX API, verify date parsing and link generation.

## Category: Cyber Security (Offensive & Defensive)
*Tools for security testing, encryption, and payload generation.*

11. **Base64 Advanced**
    - **Function:** Multi-mode Base64 tool: Standard, URL-Safe, Hex-to-Base64, Image-to-Base64 (data URI).
    - **Tests:** Test all encoding/decoding permutations with special characters.

12. **HTML Entity Encoder**
    - **Function:** Encodes/Decodes text to HTML entities (named, decimal, hex) to test XSS filters.
    - **Tests:** Verify correct conversion of characters like `< > & " '`.

13. **Hashes Generator**
    - **Function:** Computes hashes (MD5, SHA-1, SHA-256, SHA-512, RIPEMD-160) for text or file inputs using `crypto.subtle`.
    - **Tests:** Compare generated hashes against known vectors for specific strings.

14. **HMAC Generator**
    - **Function:** Generates Keyed-Hashed Message Authentication Codes using a secret key and message.
    - **Tests:** Verify HMAC output against standard test vectors (RFC 4231).

15. **Password Strength Analyzer**
    - **Function:** Analyzes password entropy, estimates crack time, and checks against common dictionary words (zxcvbn-lite implementation).
    - **Tests:** Input various password complexities, assert correct score and feedback.

16. **Secure Password Generator**
    - **Function:** Generates cryptographically strong passwords with customizable character sets (symbols, numbers, ambiguous chars).
    - **Tests:** Verify output length and character set inclusion/exclusion.

17. **CSP Builder & Analyzer**
    - **Function:** Visual editor for Content Security Policy headers. Validates syntax and highlights insecure directives (e.g., `unsafe-inline`).
    - **Tests:** Parse sample CSP strings, identify insecure policies correctly.

18. **Subresource Integrity (SRI) Generator**
    - **Function:** Generates `<script>` or `<link>` tags with `integrity` attribute (SHA-384 hash) for a given CDN URL content.
    - **Tests:** Fetch resource content, calculate hash, verify tag format.

19. **XSS Payload Generator**
    - **Function:** List of common XSS polyglots and payloads for fuzzing, categorized by context (HTML body, attribute, JS).
    - **Tests:** Verify list integrity and copy-to-clipboard functionality.

20. **SQLi Payload Generator**
    - **Function:** Collection of SQL injection payloads (Union based, Error based, Time based) for testing input fields.
    - **Tests:** Verify payload categories and string correctness.

21. **JWT Cracker (Client-Side)**
    - **Function:** Attempts to brute-force verify a JWT signature against a small dictionary of common secrets (e.g., "secret", "123456"). WARNING: For educational use.
    - **Tests:** Create signed JWT with known weak secret, verify tool finds it.

22. **PEM/DER Certificate Converter**
    - **Function:** Converts SSL certificates between PEM (ASCII) and DER (Binary) formats.
    - **Tests:** Convert known PEM to DER and back, compare byte equality.

23. **User-Agent Generator**
    - **Function:** Generates random User-Agent strings for various devices/browsers to test device-specific content.
    - **Tests:** Verify generated strings match expected patterns for selected device types.

24. **WebSocket Tester**
    - **Function:** Connect to a WS/WSS endpoint, send messages, and view the log of sent/received messages in real-time.
    - **Tests:** Mock WebSocket object, verify connection state changes and message history updates.

25. **Metadata Scrubber**
    - **Function:** Removes metadata (EXIF, etc.) from uploaded images and allows download of the clean version.
    - **Tests:** Upload image with metadata, process, verify output has no metadata.

## Category: Network Analysis & DevOps
*Tools for networking, cloud configuration, and server management.*

26. **CIDR Calculator**
    - **Function:** Calculates IP range, netmask, broadcast address, and number of hosts for a given CIDR notation (e.g., 192.168.1.0/24).
    - **Tests:** Input various CIDRs, verify calculated network details.

27. **Subnet Mask Cheat Sheet**
    - **Function:** Interactive reference for subnet masks, converting between /notation, decimal, and hex.
    - **Tests:** Verify conversion logic between formats.

28. **MAC Address Vendor Lookup**
    - **Function:** Looks up the manufacturer of a network device based on its OUI (first 6 chars of MAC).
    - **Tests:** Mock OUI database/API, test known MAC addresses.

29. **Port Number Reference**
    - **Function:** Searchable database of common TCP/UDP ports and their associated services.
    - **Tests:** specific port queries return correct service names.

30. **HTTP Status Code Reference**
    - **Function:** Searchable list of HTTP status codes with detailed explanations and solution tips.
    - **Tests:** Search logic filters correctly by code or description.

31. **Cron Expression Generator**
    - **Function:** UI builder for cron schedules (minute, hour, day, month, day of week). Converts "Every 5 minutes" to `*/5 * * * *`.
    - **Tests:** Verify specific UI settings generate correct cron strings.

32. **Chmod Calculator**
    - **Function:** Checkbox UI for file permissions (Read/Write/Execute for Owner/Group/Public) converting to octal (755) and symbolic (`rwxr-xr-x`).
    - **Tests:** Toggle checkboxes, verify octal and symbolic outputs.

33. **Dockerfile Linter**
    - **Function:** Scans a Dockerfile text for best practices (e.g., specific tags vs latest, consolidated RUN commands).
    - **Tests:** Input poor Dockerfile, verify warning generation.

34. **YAML Validator**
    - **Function:** Parses YAML input to check for syntax errors and structural validity.
    - **Tests:** Input invalid YAML, assert error message presence.

35. **Nginx Config Generator**
    - **Function:** Simple wizard to generate Nginx server blocks for static sites, proxies, or redirects.
    - **Tests:** Verify generated config syntax matches input options.

36. **Apache .htaccess Generator**
    - **Function:** Builder for common .htaccess rules (redirects, password protection, caching, compression).
    - **Tests:** Verify rule generation logic.

## Category: Web Dev & Frontend
*Tools for UI/UX, design, and markup.*

37. **Meta Tag Generator**
    - **Function:** Form-based generator for SEO meta tags (description, keywords, robots, viewport).
    - **Tests:** Verify HTML output contains all input fields correctly formatted.

38. **Open Graph Previewer**
    - **Function:** Simulates how a URL or manually entered data looks when shared on Facebook/LinkedIn/Twitter.
    - **Tests:** Render preview component with mock data.

39. **Favicon Generator**
    - **Function:** Takes an image or text/emoji and generates a favicon.ico (or png) downloadable file.
    - **Tests:** Verify canvas drawing and data URL generation.

40. **Box Shadow Generator**
    - **Function:** Visual editor for CSS `box-shadow` with multiple layers, blur, spread, and color.
    - **Tests:** Verify CSS string generation matches visual controls.

41. **Border Radius Generator**
    - **Function:** Visual editor for complex border-radius (8 values) to create organic shapes.
    - **Tests:** Verify CSS output logic.

42. **CSS Gradient Generator**
    - **Function:** Editor for linear and radial gradients. Supports multiple color stops and angles.
    - **Tests:** Verify standard CSS gradient syntax generation.

43. **CSS Filter Generator**
    - **Function:** Sliders for CSS filters (blur, brightness, contrast, grayscale, hue-rotate, etc.).
    - **Tests:** Verify filter string composition.

44. **CSS Transform Generator**
    - **Function:** Visual tools for scale, rotate, translate, and skew transformations (2D/3D).
    - **Tests:** Verify transform property string generation.

45. **HTML Table Generator**
    - **Function:** Spreadsheet-like interface to generate HTML `<table>` code with custom rows/cols and classes.
    - **Tests:** Verify generated table structure (tr, td tags).

46. **Markdown to HTML**
    - **Function:** Live converter of Markdown text to HTML source code.
    - **Tests:** Input markdown syntax, assert HTML output matches.

47. **HTML to Markdown**
    - **Function:** Converts HTML source code back to Markdown format (using Turndown or similar).
    - **Tests:** Input HTML, assert Markdown output.

48. **SVG Icon Search**
    - **Function:** Search interface for free SVG icon sets (e.g., Lucide, Heroicons) with copy-as-SVG/JSX buttons.
    - **Tests:** Mock icon list, filter logic test.

49. **Image Compressor**
    - **Function:** Compresses uploaded images (JPEG/PNG/WEBP) using browser Canvas API with quality control sliders.
    - **Tests:** Input large image, verify output blob size is smaller.

50. **Base64 Image Converter**
    - **Function:** Converts image files to Base64 data URIs and vice versa.
    - **Tests:** File to string and string to image conversion tests.

51. **Color Palette Extractor**
    - **Function:** Upload an image and extract the dominant color palette (using something like ColorThief logic).
    - **Tests:** Mock image data, verify extraction of key colors.

52. **Keycode Info**
    - **Function:** Listens for key presses and displays `event.key`, `event.code`, `event.keyCode`, and modifiers.
    - **Tests:** Simulate keyboard events, verify display updates.

53. **Lorem Ipsum Generator**
    - **Function:** Generates placeholder text (paragraphs, sentences, words) with optional HTML tags.
    - **Tests:** Verify output length and structure.

54. **Dummy Image URL Generator**
    - **Function:** Builder for placeholder image URLs (using services like via.placeholder or creating local blobs).
    - **Tests:** Generate URL with dimensions/colors, verify format.

55. **Clamp() Calculator**
    - **Function:** Calculator for CSS `clamp()` based on min/max viewport width and font sizes for fluid typography.
    - **Tests:** Input ranges, verify mathematical formula output.

## Category: Extension Development
*Tools specific to building Chrome/Web Extensions.*

56. **Manifest V3 Validator**
    - **Function:** Pasting a `manifest.json` to check against MV3 schema rules (e.g., no background pages, use service workers).
    - **Tests:** Validate compliant and non-compliant JSONs.

57. **Extension Icon Resizer**
    - **Function:** Upload a single logo and generate 16, 32, 48, 128px versions in a zip file.
    - **Tests:** Verify canvas resizing logic and zip file creation.

58. **Permissions Reference**
    - **Function:** Searchable list of `chrome` permissions and warnings they trigger.
    - **Tests:** Search filters permissions list correctly.

59. **Chrome API Search**
    - **Function:** Quick search for Chrome Extension API methods and events with links to docs.
    - **Tests:** Search logic validation.

60. **i18n Message Helper**
    - **Function:** UI to manage `_locales` messages.json files. Add key/message pairs and export JSON.
    - **Tests:** Verify JSON structure generation for i18n.

## Category: Data & Text Processing
*Tools for manipulating strings, files, and formats.*

61. **Text Diff (Enhanced)**
    - **Function:** Side-by-side text comparison highlighting added/removed lines and characters.
    - **Tests:** Compare two strings, verify diff chunks are identified.

62. **CSV to JSON**
    - **Function:** Converts CSV data (paste or file) to JSON array of objects. Supports custom delimiters.
    - **Tests:** Input CSV string, verify JSON object structure.

63. **XML to JSON**
    - **Function:** parser for XML strings converting to JSON structure.
    - **Tests:** Input XML, verify JSON output.

64. **YAML to JSON**
    - **Function:** Converts YAML to JSON.
    - **Tests:** Input YAML, verify JSON output.

65. **JSON to YAML**
    - **Function:** Converts JSON to YAML.
    - **Tests:** Input JSON, verify YAML output.

66. **Case Converter**
    - **Function:** Converts text between camelCase, PascalCase, snake_case, kebab-case, CONSTANT_CASE.
    - **Tests:** Verify transformation of strings between all formats.

67. **String Obfuscator**
    - **Function:** Encodes string into JS-compatible obfuscated code (e.g., using hex escapes or array mapping).
    - **Tests:** Obfuscate string, evaluate it to ensure it returns original.

68. **Line Sorter / Deduplicator**
    - **Function:** Sorts lines alphabetically (A-Z, Z-A), numerically, or randomizes. Removes duplicates.
    - **Tests:** Input list, verify sort order and uniqueness.

69. **Text Statistics**
    - **Function:** Counts words, characters (with/without spaces), lines, sentences, and estimated reading time.
    - **Tests:** Input sample text, verify counts.

70. **Text to Binary**
    - **Function:** Converts text to binary string (01001000...) and vice versa.
    - **Tests:** Conversion verification.

71. **Hex Editor (Viewer)**
    - **Function:** Upload a file to view its raw hexadecimal representation and ASCII translation.
    - **Tests:** Verify file reader to hex string conversion.

72. **Unicode Explorer**
    - **Function:** Searchable Unicode character table (emojis, symbols) with copy functionality and code points.
    - **Tests:** Search filters correctly by name or code.

73. **Regex Match Highlighter**
    - **Function:** Real-time regex testing that highlights matches in a text body (similar to RegExr).
    - **Tests:** Input text and regex, verify match indices.

74. **Escaping Tool**
    - **Function:** Escapes/Unescapes strings for Java, C#, Python, SQL, URL, HTML, JavaScript.
    - **Tests:** Verify escaping logic for each language mode.

75. **List Randomizer**
    - **Function:** Shuffles a list of items or picks a random winner.
    - **Tests:** Verify output list contains same elements but different order (statistically).

## Category: Programming & Utilities
*General purpose developer utilities.*

76. **Unix Timestamp Converter**
    - **Function:** Bi-directional converter for Unix Epoch timestamps (seconds/millis) to human-readable dates.
    - **Tests:** Convert specific timestamps to dates and back.

77. **Timezone Converter**
    - **Function:** Compare times across multiple timezones.
    - **Tests:** Verify offset calculations.

78. **Unit Converter (Dev)**
    - **Function:** Converts pixels to rem/em, bytes to KB/MB/GB, milliseconds to minutes/hours.
    - **Tests:** Verify conversion factors.

79. **Aspect Ratio Calculator**
    - **Function:** Calculates aspect ratios or finds new dimensions while preserving ratio.
    - **Tests:** Input 1920x1080, expect 16:9.

80. **UUID Generator**
    - **Function:** Generates UUIDs (v1, v4) singly or in bulk.
    - **Tests:** Verify UUID v4 format regex.

81. **ObjectId Generator**
    - **Function:** Generates MongoDB-style ObjectIds.
    - **Tests:** Verify 24-char hex string generation.

82. **Git Command Builder**
    - **Function:** Visual builder for complex git commands (rebase, cherry-pick flags, log formats).
    - **Tests:** Verify command string matches options.

83. **GitIgnore Generator**
    - **Function:** Select languages/frameworks to generate a combined .gitignore file (using gitignore.io data or local templates).
    - **Tests:** Combine multiple templates, verify output.

84. **License Generator**
    - **Function:** Quick text generator for common open source licenses (MIT, Apache 2.0, GPL) with user's name/year.
    - **Tests:** Verify text template interpolation.

85. **JS Minifier (Terser)**
    - **Function:** Minifies JavaScript code using a browser-compatible minifier.
    - **Tests:** Input valid JS, assert output is smaller/valid.

86. **CSS Minifier**
    - **Function:** Removes whitespace and comments from CSS.
    - **Tests:** Input CSS, assert minified string.

87. **Python to JSON (Dict)**
    - **Function:** Converts Python dictionary string (using single quotes, None, True) to valid JSON.
    - **Tests:** Input `{'a': None}`, expect `{"a": null}`.

88. **TypeScript Interface Gen**
    - **Function:** Generates TypeScript interfaces/types from a JSON object.
    - **Tests:** Input JSON, verify Interface structure.

89. **Go Struct Generator**
    - **Function:** Generates Golang struct definitions from a JSON object with json tags.
    - **Tests:** Input JSON, verify Go struct syntax.

90. **SQL Schema Generator**
    - **Function:** Infers CREATE TABLE SQL statements from a JSON object or CSV header.
    - **Tests:** Input JSON, verify SQL syntax and data type inference.

91. **cURL to Fetch**
    - **Function:** Parses a cURL command and generates equivalent JavaScript `fetch` code.
    - **Tests:** Input curl string, verify JS output.

92. **QR Code Generator**
    - **Function:** Generates QR code from text/URL with customization (colors, error correction).
    - **Tests:** Verify canvas generation from input.

93. **Barcode Generator**
    - **Function:** Generates standard barcodes (UPC, Code128) from text.
    - **Tests:** Verify SVG/Canvas output.

94. **Stopwatch / Timer**
    - **Function:** Simple countdown or stopwatch with lap times. Useful for timing manual tests.
    - **Tests:** Verify time state updates.

95. **Pomodoro Timer**
    - **Function:** Focus timer (25/5 intervals) with notifications.
    - **Tests:** Verify timer transitions.

96. **Persistent Scratchpad**
    - **Function:** Simple text area that auto-saves to `chrome.storage.local`.
    - **Tests:** Type text, mock storage save, reload, mock storage get.

97. **Todo List (Task Manager)**
    - **Function:** Simple checklist for tracking development tasks within the extension.
    - **Tests:** Add, toggle, delete items, verify state persistence.

98. **Math Expression Evaluator**
    - **Function:** Evaluates math strings (`5 * (10 + 2)`).
    - **Tests:** Input expression, verify result.

99. **Color Blindness Simulator**
    - **Function:** Applies SVG filters to the entire page (via Content Script injection) or an uploaded image to simulate protanopia, deuteranopia, etc.
    - **Tests:** Verify injection of SVG filters into DOM.

100. **CSS Grid Builder (Visual)**
     - **Function:** (Enhancement to existing or new) Drag and drop interface to define grid areas and export code.
     - **Tests:** Verify grid-template-areas generation.


---



# Red Team & Penetration Testing Tool Ideas for XCalibr

Below outlines 30 additional tool ideas focused specifically on **Red Teaming** and **Penetration Testing**. These tools are designed to fit within Chrome's MV3 constraints (client-side execution, fetch API, DOM analysis) while providing significant utility for security assessments.

## Category: Red Team / Web Vulnerability Scanning
*Tools for identifying vulnerabilities in web applications.*

1.  **Clickjacking Tester**
    -   **Function:** Loads the current target URL into an `<iframe>` within the extension popup (or a new tab) and allows the user to adjust opacity and overlay elements to verify if `X-Frame-Options` or CSP `frame-ancestors` headers are properly enforced.
    -   **Tests:** Mock header responses (allow vs deny), verify iframe load event and error handling.

2.  **IDOR Iterator**
    -   **Function:** A specialized request builder that takes a URL with a numeric or patterned ID (e.g., `/user/100`) and iterates through a specified range (e.g., 100-200), logging responses with "Success" (200 OK) status codes to identify Insecure Direct Object References.
    -   **Tests:** Mock fetch responses with varying status codes, verify list aggregation of successful hits.

3.  **Directory Buster (Lite)**
    -   **Function:** Performs a "light" directory brute-force attack against the current domain using a small, curated list of common paths (e.g., `/backup`, `/db`, `/admin`, `/test`) via `fetch`. Includes rate limiting controls.
    -   **Tests:** Mock fetch sequences, verify rate limiting logic (delays between requests).

4.  **Comment & Secret Scraper**
    -   **Function:** Scans the DOM and all loaded `<script>` files for HTML/JS comments. regex-matches for keywords like "TODO", "FIXME", "password", "key", "token", and displays them in a list.
    -   **Tests:** Inject HTML with comments into a test page, verify scraper extracts and filters them correctly.

5.  **Hidden Field Revealer**
    -   **Function:** Identifies all `<input type="hidden">` elements on the page. Provides a toggle to make them visible (`type="text"`) and highlights those containing potential sensitive data (CSRF tokens, IDs).
    -   **Tests:** Mount component with hidden inputs, verify toggle changes attribute type.

6.  **S3 Bucket Finder**
    -   **Function:** Checks for common S3 bucket naming permutations based on the domain name (e.g., `domain.com`, `domain-assets`, `domain-backup`) and checks if they are publicly accessible (HTTP 200/403 vs 404).
    -   **Tests:** Mock fetch to AWS endpoints, verify status interpretation (Open vs Protected vs Non-existent).

7.  **Git Exposure Checker**
    -   **Function:** Attempts to fetch `/.git/HEAD`, `/.git/config`, and `/.gitignore` on the current domain to check if the version control directory is exposed.
    -   **Tests:** Mock successful git config response, verify alert/status indicator.

8.  **Target="_blank" Auditor**
    -   **Function:** Scans all anchor tags on the page. Flags links that use `target="_blank"` but are missing `rel="noopener"` or `rel="noreferrer"`, warning of reverse tabnabbing vulnerabilities.
    -   **Tests:** Render links with and without attributes, verify correct identification of vulnerable links.

9.  **Storage Secret Hunter**
    -   **Function:** Scans `localStorage` and `sessionStorage` keys and values using regex patterns to identify potential JWTs, API keys, or cleartext credentials.
    -   **Tests:** Seed mock storage with dummy secrets, verify regex matching and reporting.

10. **Metafile Scanner**
    -   **Function:** Checks for the existence of standard "meta" files: `robots.txt`, `sitemap.xml`, `security.txt`, `.well-known/apple-app-site-association`, and `.well-known/security.txt`.
    -   **Tests:** Mock existence of these files, verify content preview.

11. **Proto-Pollution Fuzzer (Client-Side)**
    -   **Function:** Injects prototype pollution payloads (e.g., `__proto__[test]=polluted`) into URL parameters and checks `Object.prototype` to see if the property persisted, indicating a vulnerability.
    -   **Tests:** Mock URL parameters, simulate pollution in a safe window environment (jsdom), verify detection logic.

12. **Open Redirect Tester**
    -   **Function:** Parses current URL parameters for values that look like URLs. Replaces them with a canary token or test domain (e.g., `example.com`) and checks the response headers/location for redirection.
    -   **Tests:** Input URL with redirect param, mock fetch response with 3xx status, verify detection.

13. **API Endpoint Scraper**
    -   **Function:** Analyzes loaded JavaScript files (via `script` tags) using regex to find string patterns resembling API endpoints (e.g., `/api/v1/...`, `https://api...`) and generates a list of potential endpoints.
    -   **Tests:** Provide sample JS code with embedded API strings, verify extraction list.

14. **CSRF PoC Generator**
    -   **Function:** Users can input a target POST request (URL + body). The tool generates a standalone HTML file containing a hidden form and auto-submit script to test for Cross-Site Request Forgery.
    -   **Tests:** Input request data, verify generated HTML string contains correct form attributes and script.

15. **WAF Detector**
    -   **Function:** Sends a benign "suspicious" request (e.g., `?id=<script>alert(1)</script>`) to the target. Analyzes the 403/406 response headers and body for known WAF signatures (Cloudflare, AWS WAF, Akamai).
    -   **Tests:** Mock responses with specific WAF headers (e.g., `server: cloudflare`), verify correct WAF identification.

16. **Subdomain Takeover Checker (CNAME)**
    -   **Function:** Uses DoH (DNS over HTTPS) to resolve CNAME records for subdomains. Flags records pointing to known unregistered external services (e.g., `herokuapp.com`, `github.io`) that return 404s.
    -   **Tests:** Mock DNS response with dangling CNAME, verify flagged result.

17. **PostMessage Logger**
    -   **Function:** Injects a listener for `window.postMessage`. Logs all incoming messages to a console in the tool, highlighting those with `origin: "*"` (wildcard) which can be insecure.
    -   **Tests:** Fire `postMessage` events in test environment, verify logger captures and filters them.

18. **Source Map Detector**
    -   **Function:** Checks if loaded JS files have an associated source map (looks for `//# sourceMappingURL=` or tries appending `.map`). Alerts if source code is reconstructible.
    -   **Tests:** Mock JS file response with source map comment, verify detection.

19. **Admin Panel Finder**
    -   **Function:** Checks a predefined list of common administrative login paths (`/admin`, `/wp-admin`, `/login`, `/dashboard`, `/controlpanel`) against the current domain.
    -   **Tests:** Mock status codes (200 vs 404), verify list of found panels.

20. **HTTP Method Tester**
    -   **Function:** Sends `OPTIONS`, `TRACE`, `CONNECT` requests to the current page. Alerts if `TRACE` is enabled (Cross-Site Tracing risk) or if unexpected methods are allowed.
    -   **Tests:** Mock `OPTIONS` response with `Allow` header, verify parsing of allowed methods.

## Category: Payload Generation & Exploitation Support
*Tools to assist in creating and formatting attack vectors.*

21. **Default Credential Checker**
    -   **Function:** Searchable database of default username/passwords for common software, routers, and IoT devices (e.g., "admin/admin", "root/toor").
    -   **Tests:** Query database with device name, verify correct credential return.

22. **GraphQL Introspection Tester**
    -   **Function:** Sends a standard GraphQL introspection query (`{ __schema { types { name } } }`) to a target endpoint. Determines if the schema is publicly exposed.
    -   **Tests:** Mock successful JSON response with schema data vs error, verify status reporting.

23. **CORS Exploit Generator**
    -   **Function:** If a CORS misconfiguration is found (e.g., arbitrary origin reflected), this tool generates the specific JavaScript code (XHR/Fetch) to exploit it and exfiltrate the response.
    -   **Tests:** Input vulnerable URL and Origin, verify generated JS code syntax.

24. **Cookie Security Auditor**
    -   **Function:** Lists all cookies for the domain and grades them based on security flags: `Secure`, `HttpOnly`, `SameSite`. Highlights insecure cookies (e.g., missing `HttpOnly` on session tokens).
    -   **Tests:** Mock `chrome.cookies.getAll`, pass varied cookie objects, verify audit score/flags.

25. **Broken Link Hijacker**
    -   **Function:** Scans external links on a page. Checks their domain registration status (via Whois/DNS API) to see if the domain is available for purchase (potentially allowing link hijacking).
    -   **Tests:** Mock DNS response (NXDOMAIN), verify link is flagged as "Available/Hijackable".

26. **SPF/DMARC Analyzer**
    -   **Function:** Fetches TXT records for the domain. Parses and validates SPF and DMARC records to check for email spoofing vulnerability (e.g., `~all` or missing DMARC policy).
    -   **Tests:** Mock TXT records, verify parsing logic for SPF/DMARC syntax.

27. **Env Variable Scanner**
    -   **Function:** Scans for accidentally exposed environment files: `/.env`, `/config.js`, `/config.json`, `/server-status`.
    -   **Tests:** Mock fetch responses, verify detection of exposed files.

28. **XXE Payload Generator**
    -   **Function:** Generates common XML External Entity payloads (e.g., file retrieval, SSRF) for testing XML parsers.
    -   **Tests:** Verify generated XML strings match standard attack vectors.

29. **Command Injection Payload Generator**
    -   **Function:** specific payloads for OS command injection (e.g., separators `;`, `|`, `&&` followed by commands `id`, `whoami`, `cat /etc/passwd`), customized for Linux vs Windows.
    -   **Tests:** Select OS, verify payload formatting.

30. **JWT Attack Advisor**
    -   **Function:** Accepts a JWT. Decodes it and suggests specific tests based on its structure: "None" algorithm attack, Weak secret brute-force (link to cracker), Key confusion attack (HMAC vs RSA).
    -   **Tests:** Input JWTs with specific flaws (alg: none), verify correct advice is generated.

# Final Task
- Run all tests and fix anything that's broken. Run tests until everything is fixed and then build the project.