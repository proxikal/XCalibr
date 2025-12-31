

### URL Encoder/Decoder Analysis
**Status:** Functional
**Simulation Log:** I paste a crafted parameter and toggle encode/decode; output updates immediately.
**Critique:**
* **What's Missing:** Base64URL and path-encoding modes, plus RFC 3986 vs 2396 presets.
* **Data Gaps:** No breakdown of encoded bytes or invalid sequences.
**Solution & Design:**
* **Layout Proposal:** Add a mode selector with presets and a "Show diff" toggle.
* **Data Presentation:** Inline diff highlighting for changed characters and hex view for bytes.

### Param Analyzer Analysis
**Status:** Functional
**Simulation Log:** On Juice Shop search, I edit query params and open the updated URL; the tab navigates as expected.
**Critique:**
* **What's Missing:** Parameter fuzz presets, type hints (int/uuid/bool), and bulk import/export.
* **Data Gaps:** No encoded vs decoded display, no server response preview.
**Solution & Design:**
* **Layout Proposal:** Add a split view with param table on the left and preview URL on the right.
* **Data Presentation:** Provide a toggle to show decoded/encoded values side-by-side.

### Link Extractor Analysis
**Status:** Functional
**Simulation Log:** On DVWA, Refresh lists internal/external anchors; dynamic JS-generated links are not included.
**Critique:**
* **What's Missing:** Extraction from onclick handlers, SPA routers, and sitemap references.
* **Data Gaps:** No HTTP status sampling, no link depth or DOM context.
**Solution & Design:**
* **Layout Proposal:** Add a "Context" column showing the DOM selector or parent element.
* **Data Presentation:** Use a filterable table with status badges and export options.

### DOM Snapshot Analysis
**Status:** Functional
**Simulation Log:** I capture the page HTML after login; scripts are stripped and the snapshot is copied out.
**Critique:**
* **What's Missing:** Shadow DOM capture, raw vs sanitized toggle, and diff against previous snapshots.
* **Data Gaps:** No timestamped history, no resource inlining option.
**Solution & Design:**
* **Layout Proposal:** Add a "Snapshot History" list with compare buttons.
* **Data Presentation:** Use a side-by-side diff viewer for old/new snapshots.

### Asset Mapper Analysis
**Status:** Functional
**Simulation Log:** On Juice Shop, Refresh lists images/scripts/styles from the DOM; preloads and CSS background assets are not captured.
**Critique:**
* **What's Missing:** Discovery of CSS background URLs, prefetch/preload, and inline scripts.
* **Data Gaps:** No asset sizes, caching headers, or origin grouping.
**Solution & Design:**
* **Layout Proposal:** Add a filter bar for type/origin and a size column.
* **Data Presentation:** Use grouped lists by origin with expandable asset metadata.

### Request Log Analysis
**Status:** Limited by MV3
**Simulation Log:** With the tool open, resource timing entries appear; cross-origin responses show limited timing and often no status.
**Critique:**
* **What's Missing:** Full request/response headers, request bodies, and websocket visibility.
* **Data Gaps:** Missing TTFB in many cases, no redirect chain, no cache hit indicators.
**Solution & Design:**
* **Layout Proposal:** Add a "Details" drawer with tabs for Timing, Headers, and Initiator.
* **Data Presentation:** Waterfall chart plus a compact request summary row with badges (cached, redirect, error).

### Payload Replay Analysis
**Status:** Functional
**Simulation Log:** I replay a POST to a DVWA endpoint; the request succeeds but does not include user cookies by default, so authenticated APIs may fail.
**Critique:**
* **What's Missing:** Cookie/session include toggle, redirects visibility, and raw HTTP preview.
* **Data Gaps:** No latency metrics, no request/response size, no TLS/cert info.
**Solution & Design:**
* **Layout Proposal:** Add a "Session" section with credentials toggle and a raw request preview.
* **Data Presentation:** Response panel should support JSON tree view with syntax highlighting and collapsible headers.

### CORS Check Analysis
**Status:** Limited by MV3
**Action:** Remove this tool from the extension as it's severely limited by MV3 Restrictions. Make sure to remove all entries of the tool, the tools test units and edit the tool out of the registry. Add a note in the code somewhere in the cyber security tools explaining why this tool had to be removed.

### Base64 Advanced Analysis
**Status:** Functional
**Simulation Log:** I encode a JWT segment and decode it; URL-safe mode works and image mode produces a data URL.
**Critique:**
* **What's Missing:** Base64URL decode/encode auto-detect, chunking, and file output for binary.
* **Data Gaps:** No input validation hints, no byte length stats.
**Solution & Design:**
* **Layout Proposal:** Add a small "Info" strip with byte length and charset detection.
* **Data Presentation:** Provide a hex preview toggle for binary inputs.

### HTML Entity Encoder Analysis
**Status:** Functional
**Simulation Log:** I encode a script payload and decode HTML entities; output is correct using DOMParser.
**Critique:**
* **What's Missing:** Full named-entity set, numeric entity detection report, and context-aware encoding (attribute vs text).
* **Data Gaps:** No report of non-ASCII entities, no decode warnings for malformed entities.
**Solution & Design:**
* **Layout Proposal:** Add a mode selector for "Context: text/attr/URL".
* **Data Presentation:** Highlight encoded characters inline with tooltips.

### Hashes Generator Analysis
**Status:** Functional
**Simulation Log:** I hash a wordlist entry; SHA-256/384/512 are generated via WebCrypto.
**Critique:**
* **What's Missing:** MD5 (legacy), SHA-3, and file hashing.
* **Data Gaps:** No salt support, no timing/throughput metrics.
**Solution & Design:**
* **Layout Proposal:** Add tabs for "Text" vs "File" with a drag/drop zone.
* **Data Presentation:** Display results in a table with quick-copy per algorithm.

### HMAC Generator Analysis
**Status:** Functional
**Simulation Log:** I compute HMAC-SHA256 with a hex key; output matches expected.
**Critique:**
* **What's Missing:** Base64 key input, key length guidance, and verify mode.
* **Data Gaps:** No output in Base64/URL-safe variants, no key entropy estimate.
**Solution & Design:**
* **Layout Proposal:** Add output format toggles and a "Verify" input to compare signatures.
* **Data Presentation:** Show a compact key strength indicator.

### Password Strength Analysis
**Status:** Functional
**Simulation Log:** I test weak passwords; the tool flags common/dictionary entries and estimates crack time.
**Critique:**
* **What's Missing:** zxcvbn-style pattern matching (keyboard, dates), breach corpus check.
* **Data Gaps:** No guessing rate assumptions, no policy compliance checks.
**Solution & Design:**
* **Layout Proposal:** Add a policy checklist section with configurable rules.
* **Data Presentation:** Display a timeline of crack time under different attack models.

### Password Generator Analysis
**Status:** Functional
**Simulation Log:** I generate a 16-char password with symbols and copy it; history records last 5.
**Critique:**
* **What's Missing:** Passphrase mode, exclude ambiguous chars, and regex policy templates.
* **Data Gaps:** No per-character class distribution, no entropy per policy.
**Solution & Design:**
* **Layout Proposal:** Add tabs for "Password" vs "Passphrase" with wordlist length controls.
* **Data Presentation:** Show a mini histogram of character classes.

### CSP Builder Analysis
**Status:** Functional
**Simulation Log:** I build a strict CSP header and analyze an existing CSP; warnings are simple string checks.
**Critique:**
* **What's Missing:** Nonce/hash helpers, report-uri/report-to builder, and strict-dynamic guidance.
* **Data Gaps:** No parsing of multiple policies, no directive-specific validation, no duplicate detection.
**Solution & Design:**
* **Layout Proposal:** Split into "Builder" and "Analyzer" tabs with directive cards.
* **Data Presentation:** Use a parsed tree view with warning badges per directive.

### SRI Generator Analysis
**Status:** Functional
**Simulation Log:** I paste a JS file and generate SHA-384 SRI; tag output is correct.
**Critique:**
* **What's Missing:** Fetch-from-URL hashing (with host permissions), file upload, and multiple hash outputs.
* **Data Gaps:** No integrity for multiple resources, no size or content hash preview.
**Solution & Design:**
* **Layout Proposal:** Add a resource list where each row can be URL or file.
* **Data Presentation:** Display a table with algorithm, hash, and copy buttons.

### XSS Payload Analysis
**Status:** Functional
**Simulation Log:** I select a DOM-based payload for Juice Shop and copy it; encoding toggles apply.
**Critique:**
* **What's Missing:** Context presets (HTML/attr/JS/URL), WAF evasion variants, and payload notes by sink type.
* **Data Gaps:** No compatibility tags (reflected/stored/DOM), no sanitization bypass hints.
**Solution & Design:**
* **Layout Proposal:** Add a "Context" selector that filters payloads by sink.
* **Data Presentation:** Use a payload card grid with tags for context and risk.

### SQLi Payload Analysis
**Status:** Functional
**Simulation Log:** I copy a time-based payload and test on DVWA; payloads are basic and manual.
**Critique:**
* **What's Missing:** DBMS-specific variants, comment styles, and encoding toggles.
* **Data Gaps:** No technique guidance (union/error/boolean), no payload metadata.
**Solution & Design:**
* **Layout Proposal:** Add DBMS tabs (MySQL/Postgres/MSSQL/Oracle).
* **Data Presentation:** Display payloads with tags for technique and expected response.

### User-Agent Generator Analysis
**Status:** Functional
**Simulation Log:** I pick a mobile UA and copy it for manual use; the tool does not apply it to requests.
**Critique:**
* **What's Missing:** MV3-compliant request override via declarativeNetRequest rules and per-tab scoping.
* **Data Gaps:** No UA-CH hints, no platform/viewport pairing.
**Solution & Design:**
* **Layout Proposal:** Add "Apply to tab" toggle that installs/removes a DNR rule.
* **Data Presentation:** Show full UA plus derived UA-CH fields in a collapsible section.

### JWT Cracker Analysis
**Status:** Functional
**Simulation Log:** I test an HS256 token with a small wordlist; it finds the secret if present.
**Critique:**
* **What's Missing:** JWT decode view, base64url padding fixes, and rule-based mutations.
* **Data Gaps:** No keyspace stats, no time estimates, no multi-threading/worker support.
**Solution & Design:**
* **Layout Proposal:** Add a top "Token Inspector" panel with header/payload decoded.
* **Data Presentation:** Show progress with attempts/sec and ETA.

### PEM/DER Converter Analysis
**Status:** Functional
**Simulation Log:** I paste a PEM cert and convert to DER hex; basic subject/issuer fields are shown.
**Critique:**
* **What's Missing:** Full ASN.1 parsing, base64 DER input, and multi-cert bundle support.
* **Data Gaps:** No validity dates, SANs, key usage, or fingerprints.
**Solution & Design:**
* **Layout Proposal:** Add a "Certificate Details" accordion with common X.509 fields.
* **Data Presentation:** Tree view of ASN.1 nodes with hex and decoded values.

### WebSocket Tester Analysis
**Status:** Limited by MV3
**Action:** Remove this tool from the extension as it's severely limited by MV3 Restrictions. Make sure to remove all entries of the tool, the tools test units and edit the tool out of the registry. Add a note in the code somewhere in the cyber security tools explaining why this tool had to be removed.

### Metadata Scrubber Analysis
**Status:** Limited by MV3
**Simulation Log:** I upload a JPEG; EXIF is detected and removed, but PNG/GIF/WebP metadata handling is minimal.
**Critique:**
* **What's Missing:** Full EXIF parser, GPS redaction controls, and support for GIF/WebP metadata removal.
* **Data Gaps:** No before/after metadata diff, no ICC/profile details.
**Solution & Design:**
* **Layout Proposal:** Add a "Metadata Summary" panel and a diff view after scrubbing.
* **Data Presentation:** Key/value table with sections (EXIF/GPS/ICC) and color-coded removals.

### Clickjacking Tester Analysis
**Status:** Functional
**Simulation Log:** I test a DVWA page; headers are checked and an iframe preview attempts to load the target.
**Critique:**
* **What's Missing:** Report-Only CSP detection, frame-ancestors parser, and visual overlay templates.
* **Data Gaps:** No redirect chain, no response status, no XFO alternative values (ALLOW-FROM).
**Solution & Design:**
* **Layout Proposal:** Add a "Header Analysis" subpanel with parsed XFO/CSP results.
* **Data Presentation:** Use a compact status checklist and a warning banner if framing succeeds.

### IDOR Iterator Analysis
**Status:** Functional
**Simulation Log:** I iterate `/api/users/{ID}` on a test API; only 200/201 responses are surfaced and auth cookies are not included.
**Critique:**
* **What's Missing:** Auth header/cookie injection, concurrency controls, and response sampling.
* **Data Gaps:** No response body preview, no rate-limit detection, no 403/401 visibility.
**Solution & Design:**
* **Layout Proposal:** Add a "Request Settings" panel with headers, cookies, and concurrency.
* **Data Presentation:** Results table with status, size, and optional body snippet toggle.

### Directory Buster Analysis
**Status:** Functional
**Simulation Log:** I scan a Juice Shop host; paths returning non-404 are listed, but auth and custom headers are absent.
**Critique:**
* **What's Missing:** Wordlist management, extension detection, and status code filters.
* **Data Gaps:** No response title/headers, no redirect location, no concurrency stats.
**Solution & Design:**
* **Layout Proposal:** Add tabs for "Wordlist" and "Scan Settings" with filters.
* **Data Presentation:** Table with status badges and expandable response metadata.

### Prototype Pollution Fuzzer Analysis
**Status:** Broken
**Simulation Log:** I run tests on a page; the tool only simulates payloads and never actually mutates prototypes, so no vulnerabilities are detected.
**Critique:**
* **What's Missing:** Real sink testing against page code paths, and controlled merge invocation with payload injection.
* **Data Gaps:** No runtime detection of polluted properties, no trace to code location.
**Solution & Design:**
* **Layout Proposal:** Add a "Test Harness" panel to inject payloads into user-specified parameters or JSON bodies.
* **Data Presentation:** Show before/after prototype checks with a clear "polluted" indicator and stack trace.

### Open Redirect Tester Analysis
**Status:** Functional
**Simulation Log:** I generate payloaded URLs for a redirect endpoint and open them manually to observe behavior.
**Critique:**
* **What's Missing:** Automatic redirect verification via background fetch (manual redirect handling).
* **Data Gaps:** No HTTP status/Location header capture, no normalization of open redirect patterns.
**Solution & Design:**
* **Layout Proposal:** Add a "Verify" button that tests redirects and records Location.
* **Data Presentation:** Results table with payload, status, and resolved redirect target.

### API Endpoint Scraper Analysis
**Status:** Limited by MV3
**Simulation Log:** Scanning a SPA finds inline endpoints, but fetching cross-origin scripts often fails due to CORS in the content context.
**Critique:**
* **What's Missing:** Background fetch for external scripts, source map discovery, and GraphQL schema endpoint hints.
* **Data Gaps:** No endpoint confidence score, no path normalization, no auth header detection.
**Solution & Design:**
* **Layout Proposal:** Add a "Source" filter and a toggle for background script fetching.
* **Data Presentation:** List endpoints with source badges and optional path grouping.

### CSRF PoC Generator Analysis
**Status:** Functional
**Simulation Log:** I scan forms on DVWA and generate a PoC; it includes hidden inputs but does not handle JSON APIs or file uploads.
**Critique:**
* **What's Missing:** JSON/form-data modes, token regeneration hints, and multi-step workflow support.
* **Data Gaps:** No cookie/Origin/Referer analysis, no CSRF token detection.
**Solution & Design:**
* **Layout Proposal:** Add a mode selector (form, JSON, multipart) and a token detection summary.
* **Data Presentation:** Render the PoC with syntax highlighting and copy/download buttons.

### WAF Detector Analysis
**Status:** Functional
**Simulation Log:** I scan a target URL; it compares headers/cookies to known signatures but does not test payload blocking.
**Critique:**
* **What's Missing:** Active probing with benign test payloads, body pattern checks, and confidence scoring.
* **Data Gaps:** No response body sampling, no per-indicator weights, no CDN vs WAF disambiguation.
**Solution & Design:**
* **Layout Proposal:** Add "Passive" and "Active" tabs with safe test modes.
* **Data Presentation:** Use a score bar with matched indicators listed below.

### Subdomain Takeover Checker Analysis
**Status:** Broken
**Simulation Log:** I submit a list of subdomains; DNS lookup runs, but HTTP fetch uses a missing `xcalibr-fetch` handler, causing errors or false positives.
**Critique:**
* **What's Missing:** Implemented fetch handler, HTTP status capture, and service-specific verification steps.
* **Data Gaps:** No TXT/CAA checks, no resolution chain, no ownership proof guidance.
**Solution & Design:**
* **Layout Proposal:** Add a "Verification Steps" panel per provider with next actions.
* **Data Presentation:** Display DNS records and HTTP fingerprint in a two-column layout.

### PostMessage Logger Analysis
**Status:** Functional
**Simulation Log:** I start listening and trigger postMessage events from an embedded iframe; messages are captured with origin and type.
**Critique:**
* **What's Missing:** Source window identification, allowlist/denylist filters, and structured JSON viewer.
* **Data Gaps:** No event origin validation checks, no correlation to target window.
**Solution & Design:**
* **Layout Proposal:** Add filter chips for origin/source/type and a "Decoded JSON" panel.
* **Data Presentation:** Use collapsible JSON tree with line wrapping and copy-as-JSON.
