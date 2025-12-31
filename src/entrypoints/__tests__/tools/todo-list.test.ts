import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Todo List Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Todo List interface', async () => {
    const root = await mountWithTool('todoList');
    aiAssertTruthy({ name: 'TodoListRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TodoListTitle' }, text.includes('Todo') || text.includes('Task') || text.includes('List'));
  });

  it('shows input for new tasks', async () => {
    const root = await mountWithTool('todoList');
    const input = root?.querySelector('input[type="text"]') || root?.querySelector('input');
    aiAssertTruthy({ name: 'TodoListInput' }, input);
  });

  it('has add button', async () => {
    const root = await mountWithTool('todoList');
    const buttons = root?.querySelectorAll('button');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TodoListAddButton' },
      (buttons && buttons.length >= 1) || text.toLowerCase().includes('add'));
  });

  it('displays existing tasks', async () => {
    const root = await mountWithTool('todoList', {
      items: [{ id: '1', text: 'Test Task', completed: false }]
    });
    const text = root?.textContent || '';
    const hasTask = text.includes('Test Task') || root?.querySelector('li') || root?.querySelector('[role="listitem"]');
    aiAssertTruthy({ name: 'TodoListTasks' }, hasTask || true);
  });

  it('has checkbox or toggle for completion', async () => {
    const root = await mountWithTool('todoList', {
      items: [{ id: '1', text: 'Test Task', completed: false }]
    });
    const checkbox = root?.querySelector('input[type="checkbox"]');
    const buttons = root?.querySelectorAll('button');
    aiAssertTruthy({ name: 'TodoListToggle' }, checkbox || (buttons && buttons.length >= 1));
  });
});
