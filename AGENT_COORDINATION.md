# Agent Coordination File

This file coordinates parallel agent work to prevent file conflicts.

## Agent Assignments

### Agent 1: Batch A (Tools #4-10) - 7 tools ✓ COMPLETE
- [DONE] #4 - Comment & Secret Scraper → `CommentSecretScraperTool`
- [DONE] #5 - Hidden Field Revealer → `HiddenFieldRevealerTool`
- [DONE] #6 - S3 Bucket Finder → `S3BucketFinderTool`
- [DONE] #7 - Git Exposure Checker → `GitExposureCheckerTool`
- [DONE] #8 - Target="_blank" Auditor → `TargetBlankAuditorTool`
- [DONE] #9 - Storage Secret Hunter → `StorageSecretHunterTool`
- [DONE] #10 - Metafile Scanner → `MetafileScannerTool`

**Registry File**: `src/entrypoints/content/toolregistry/redteam-batch-a-tools.tsx`

---

### Agent 2: Batch B (Tools #11-17) - 7 tools ✓ COMPLETE
- [DONE] #11 - Proto-Pollution Fuzzer → `ProtoPollutionFuzzerTool`
- [DONE] #12 - Open Redirect Tester → `OpenRedirectTesterTool`
- [DONE] #13 - API Endpoint Scraper → `ApiEndpointScraperTool`
- [DONE] #14 - CSRF PoC Generator → `CsrfPocGeneratorTool`
- [DONE] #15 - WAF Detector → `WafDetectorTool`
- [DONE] #16 - Subdomain Takeover Checker → `SubdomainTakeoverCheckerTool`
- [DONE] #17 - PostMessage Logger → `PostMessageLoggerTool`

**Registry File**: `src/entrypoints/content/toolregistry/redteam-batch-b-tools.tsx`

---

### Agent 3: Batch C (Tools #18-23) - 6 tools ✓ COMPLETE
- [DONE] #18 - Source Map Detector → `SourceMapDetectorTool`
- [DONE] #19 - Admin Panel Finder → `AdminPanelFinderTool`
- [DONE] #20 - HTTP Method Tester → `HttpMethodTesterTool`
- [DONE] #21 - Default Credential Checker → `DefaultCredentialCheckerTool`
- [DONE] #22 - GraphQL Introspection Tester → `GraphqlIntrospectionTesterTool`
- [DONE] #23 - CORS Exploit Generator → `CorsExploitGeneratorTool`

**Registry File**: `src/entrypoints/content/toolregistry/redteam-batch-c-tools.tsx`

---

### Agent 4: Batch D (Tools #24-30) - 7 tools ✓ COMPLETE
- [DONE] #24 - Cookie Security Auditor → `CookieSecurityAuditorTool`
- [DONE] #25 - Broken Link Hijacker → `BrokenLinkHijackerTool`
- [DONE] #26 - SPF/DMARC Analyzer → `SpfDmarcAnalyzerTool`
- [DONE] #27 - Env Variable Scanner → `EnvVariableScannerTool`
- [DONE] #28 - XXE Payload Generator → `XxePayloadGeneratorTool`
- [DONE] #29 - Command Injection Payload Generator → `CommandInjectionPayloadTool`
- [DONE] #30 - JWT Attack Advisor → `JwtAttackAdvisorTool`

**Registry File**: `src/entrypoints/content/toolregistry/redteam-batch-d-tools.tsx`

---

## Integration Complete ✓

All 27 Red Team tools have been implemented and integrated:

1. **Tool Registry**: Updated `src/entrypoints/content/toolregistry/index.ts` to import all batch registries
2. **Menu**: Updated `src/entrypoints/content/menu.ts` with Red Team menu section
3. **Build**: Successful (1.32 MB)

---

## File Ownership Rules (Reference)

### Files Each Agent Creates (NO CONFLICTS - unique per agent):
1. Tool components: `src/entrypoints/content/Tools/<ToolName>Tool.tsx`
2. Test files: `src/entrypoints/__tests__/tools/<tool-name>.test.ts`
3. Batch registry: `src/entrypoints/content/toolregistry/redteam-batch-{a|b|c|d}-tools.tsx`

### Shared Files (APPEND ONLY with batch markers):

**`src/entrypoints/content/Tools/index.ts`**:
- Agent 1: Add exports at END with comment `// === BATCH A: Red Team Tools #4-10 ===`
- Agent 2: Add exports at END with comment `// === BATCH B: Red Team Tools #11-17 ===`
- Agent 3: Add exports at END with comment `// === BATCH C: Red Team Tools #18-23 ===`
- Agent 4: Add exports at END with comment `// === BATCH D: Red Team Tools #24-30 ===`

**`src/entrypoints/content/Tools/tool-types.ts`**:
- Agent 1: Add types at END with comment `// === BATCH A: Red Team Tools #4-10 ===`
- Agent 2: Add types at END with comment `// === BATCH B: Red Team Tools #11-17 ===`
- Agent 3: Add types at END with comment `// === BATCH C: Red Team Tools #18-23 ===`
- Agent 4: Add types at END with comment `// === BATCH D: Red Team Tools #24-30 ===`
