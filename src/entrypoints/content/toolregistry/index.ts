// Re-export types
export { TOOL_DEFAULT_POSITION } from './types';
export type { ToolRegistryEntry, ToolRegistryHandlers } from './types';

// Import category builders
import { buildWebDevTools } from './webdev-tools';
import { buildFrontendTools } from './frontend-tools';
import { buildBackendTools } from './backend-tools';
import { buildCybersecTools } from './cybersec-tools';
import { buildOsintTools } from './osint-tools';
import { buildNetworkTools } from './network-tools';
import { buildDevopsTools } from './devops-tools';
import { buildDatabaseTools } from './database-tools';
import { buildDataTextTools } from './datatext-tools';
import { buildExtensionDevTools } from './extensiondev-tools';
// Red Team batch registries
import { buildRedteamBatchATools } from './redteam-batch-a-tools';
import { buildRedTeamBatchBTools } from './redteam-batch-b-tools';
import { buildRedteamBatchCTools } from './redteam-batch-c-tools';
import { buildRedteamBatchDTools } from './redteam-batch-d-tools';
import { buildRedteamBatchETools } from './redteam-batch-e-tools';

import type { ToolRegistryEntry, ToolRegistryHandlers } from './types';

/**
 * Builds the complete tool registry by combining all category-specific tools.
 * This maintains backward compatibility with the original buildToolRegistry function.
 */
export const buildToolRegistry = (handlers: ToolRegistryHandlers): ToolRegistryEntry[] => [
  ...buildWebDevTools(handlers),
  ...buildFrontendTools(),
  ...buildBackendTools(handlers),
  ...buildCybersecTools(),
  ...buildOsintTools(),
  ...buildNetworkTools(),
  ...buildDevopsTools(),
  ...buildDatabaseTools(),
  ...buildDataTextTools(),
  ...buildExtensionDevTools(),
  // Red Team tools (batches A-E)
  ...buildRedteamBatchATools(),
  ...buildRedTeamBatchBTools(),
  ...buildRedteamBatchCTools(),
  ...buildRedteamBatchDTools(),
  ...buildRedteamBatchETools()
];

// Re-export individual category builders for direct access if needed
export {
  buildWebDevTools,
  buildFrontendTools,
  buildBackendTools,
  buildCybersecTools,
  buildOsintTools,
  buildNetworkTools,
  buildDevopsTools,
  buildDatabaseTools,
  buildDataTextTools,
  buildExtensionDevTools,
  // Red Team batch builders
  buildRedteamBatchATools,
  buildRedTeamBatchBTools,
  buildRedteamBatchCTools,
  buildRedteamBatchDTools,
  buildRedteamBatchETools
};
