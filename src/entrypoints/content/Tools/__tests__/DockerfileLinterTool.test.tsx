import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('DockerfileLinterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('dockerfileLinter');
      aiAssertTruthy({ name: 'DockerMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'DockerTitle' }, text, 'Dockerfile Linter');
    });

    it('renders Lint button', async () => {
      const root = await mountWithTool('dockerfileLinter');
      const lintBtn = findButtonByText(root!, 'Lint Dockerfile');
      aiAssertTruthy({ name: 'DockerLintBtn' }, lintBtn);
    });

    it('renders textarea', async () => {
      const root = await mountWithTool('dockerfileLinter');
      const textarea = root?.querySelector('textarea');
      aiAssertTruthy({ name: 'DockerTextarea' }, textarea);
    });
  });

  describe('Linting - Valid Dockerfile', () => {
    it('passes valid Dockerfile', async () => {
      const validDockerfile = `FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]`;

      const root = await mountWithTool('dockerfileLinter', {
        input: validDockerfile
      });
      const lintBtn = findButtonByText(root!, 'Lint');
      lintBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { warnings?: string[] }>;
        return toolData.dockerfileLinter?.warnings !== undefined;
      });
      const warnings = (stored?.toolData as Record<string, { warnings?: string[] }> | undefined)
        ?.dockerfileLinter?.warnings || [];
      // Should have no or minimal warnings for a valid Dockerfile
      aiAssertTruthy({ name: 'DockerValidNoWarnings' }, warnings.length < 3);
    });
  });

  describe('Linting - Warnings', () => {
    it('warns about using latest tag', async () => {
      const root = await mountWithTool('dockerfileLinter', {
        input: 'FROM ubuntu:latest'
      });
      const lintBtn = findButtonByText(root!, 'Lint Dockerfile');
      lintBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { warnings?: string[] }>;
        return toolData.dockerfileLinter?.warnings !== undefined && toolData.dockerfileLinter.warnings.length > 0;
      });
      const warnings = (stored?.toolData as Record<string, { warnings?: string[] }> | undefined)
        ?.dockerfileLinter?.warnings || [];
      const hasLatestWarning = warnings.some(w => w.toLowerCase().includes('latest'));
      aiAssertTruthy({ name: 'DockerLatestTag' }, hasLatestWarning);
    });

    it('warns about using ADD instead of COPY', async () => {
      const root = await mountWithTool('dockerfileLinter', {
        input: 'FROM alpine\nADD . /app'
      });
      const lintBtn = findButtonByText(root!, 'Lint Dockerfile');
      lintBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { warnings?: string[] }>;
        return toolData.dockerfileLinter?.warnings !== undefined && toolData.dockerfileLinter.warnings.length > 0;
      });
      const warnings = (stored?.toolData as Record<string, { warnings?: string[] }> | undefined)
        ?.dockerfileLinter?.warnings || [];
      const hasAddWarning = warnings.some(w => w.toLowerCase().includes('copy'));
      aiAssertTruthy({ name: 'DockerAddWarning' }, hasAddWarning);
    });

    it('warns about running as root', async () => {
      const root = await mountWithTool('dockerfileLinter', {
        input: 'FROM alpine\nRUN apk add curl'
      });
      const lintBtn = findButtonByText(root!, 'Lint Dockerfile');
      lintBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { warnings?: string[] }>;
        return toolData.dockerfileLinter?.warnings !== undefined && toolData.dockerfileLinter.warnings.length > 0;
      });
      const warnings = (stored?.toolData as Record<string, { warnings?: string[] }> | undefined)
        ?.dockerfileLinter?.warnings || [];
      const hasRootWarning = warnings.some(w => w.toLowerCase().includes('root') || w.toLowerCase().includes('user'));
      aiAssertTruthy({ name: 'DockerRootWarning' }, hasRootWarning);
    });
  });

  describe('Persistence', () => {
    it('persists input', async () => {
      const root = await mountWithTool('dockerfileLinter', {
        input: 'FROM alpine:3.18'
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { input?: string }>;
        return toolData.dockerfileLinter?.input === 'FROM alpine:3.18';
      });
      aiAssertTruthy({ name: 'DockerPersist' }, stored);
    });
  });
});
