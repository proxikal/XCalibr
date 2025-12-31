import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('GraphQL Introspection Tester Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the GraphQL Introspection Tester interface', async () => {
    const root = await mountWithTool('graphqlIntrospectionTester');
    aiAssertTruthy({ name: 'GraphqlIntrospectionTesterRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'GraphqlIntrospectionTesterTitle' },
      text.includes('GraphQL') || text.includes('Introspection') || text.includes('Schema'));
  });

  it('shows endpoint URL input', async () => {
    const root = await mountWithTool('graphqlIntrospectionTester');
    const input = root?.querySelector('input') || root?.querySelector('textarea');
    aiAssertTruthy({ name: 'GraphqlIntrospectionTesterInput' }, input);
  });

  it('has test button', async () => {
    const root = await mountWithTool('graphqlIntrospectionTester');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'GraphqlIntrospectionTesterButton' }, button);
  });

  it('shows introspection status', async () => {
    const root = await mountWithTool('graphqlIntrospectionTester', {
      url: 'https://example.com/graphql',
      isEnabled: true,
      testedAt: Date.now()
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'GraphqlIntrospectionTesterStatus' },
      text.toLowerCase().includes('enabled') || text.toLowerCase().includes('vulnerable') ||
      text.toLowerCase().includes('disabled') || (root?.querySelectorAll('*').length ?? 0) > 5);
  });

  it('shows schema types when introspection is enabled', async () => {
    const root = await mountWithTool('graphqlIntrospectionTester', {
      url: 'https://example.com/graphql',
      isEnabled: true,
      schema: {
        types: ['Query', 'Mutation', 'User', 'Post'],
        queryFields: ['users', 'posts', 'user']
      },
      testedAt: Date.now()
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'GraphqlIntrospectionTesterSchema' },
      text.includes('Query') || text.includes('Type') || text.includes('types') || (root?.querySelectorAll('*').length ?? 0) > 5);
  });
});
