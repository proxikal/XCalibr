import React, { useState } from 'react';

export type TodoItem = {
  id: string;
  text: string;
  completed: boolean;
  createdAt: number;
};

export type TodoListData = {
  items?: TodoItem[];
  filter?: 'all' | 'active' | 'completed';
};

type Props = {
  data: TodoListData | undefined;
  onChange: (data: TodoListData) => void;
};

const generateId = () => Math.random().toString(36).substr(2, 9);

const TodoList: React.FC<Props> = ({ data, onChange }) => {
  const items = data?.items ?? [];
  const filter = data?.filter ?? 'all';
  const [newTaskText, setNewTaskText] = useState('');

  const handleAddTask = () => {
    if (!newTaskText.trim()) return;

    const newItem: TodoItem = {
      id: generateId(),
      text: newTaskText.trim(),
      completed: false,
      createdAt: Date.now()
    };

    onChange({ ...data, items: [...items, newItem] });
    setNewTaskText('');
  };

  const handleToggle = (id: string) => {
    onChange({
      ...data,
      items: items.map(item =>
        item.id === id ? { ...item, completed: !item.completed } : item
      )
    });
  };

  const handleDelete = (id: string) => {
    onChange({
      ...data,
      items: items.filter(item => item.id !== id)
    });
  };

  const handleClearCompleted = () => {
    onChange({
      ...data,
      items: items.filter(item => !item.completed)
    });
  };

  const filteredItems = items.filter(item => {
    if (filter === 'active') return !item.completed;
    if (filter === 'completed') return item.completed;
    return true;
  });

  const activeCount = items.filter(item => !item.completed).length;
  const completedCount = items.filter(item => item.completed).length;

  return (
    <div className="space-y-3">
      <div className="flex gap-2">
        <input
          type="text"
          value={newTaskText}
          onChange={(e) => setNewTaskText(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleAddTask()}
          placeholder="Add a new task..."
          className="flex-1 px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
        />
        <button
          onClick={handleAddTask}
          disabled={!newTaskText.trim()}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
        >
          Add
        </button>
      </div>

      <div className="flex gap-1 text-xs">
        <button
          onClick={() => onChange({ ...data, filter: 'all' })}
          className={`px-2 py-1 rounded ${
            filter === 'all' ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300'
          }`}
        >
          All ({items.length})
        </button>
        <button
          onClick={() => onChange({ ...data, filter: 'active' })}
          className={`px-2 py-1 rounded ${
            filter === 'active' ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300'
          }`}
        >
          Active ({activeCount})
        </button>
        <button
          onClick={() => onChange({ ...data, filter: 'completed' })}
          className={`px-2 py-1 rounded ${
            filter === 'completed' ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300'
          }`}
        >
          Done ({completedCount})
        </button>
      </div>

      <div className="space-y-1 max-h-48 overflow-y-auto">
        {filteredItems.length === 0 ? (
          <div className="text-center text-gray-500 text-sm py-4">
            {filter === 'all' ? 'No tasks yet' : `No ${filter} tasks`}
          </div>
        ) : (
          filteredItems.map(item => (
            <div
              key={item.id}
              className="flex items-center gap-2 p-2 bg-[#1a1a2e] rounded group"
            >
              <input
                type="checkbox"
                checked={item.completed}
                onChange={() => handleToggle(item.id)}
                className="rounded bg-gray-700 border-gray-600"
              />
              <span
                className={`flex-1 text-sm ${
                  item.completed ? 'text-gray-500 line-through' : 'text-white'
                }`}
              >
                {item.text}
              </span>
              <button
                onClick={() => handleDelete(item.id)}
                className="opacity-0 group-hover:opacity-100 text-red-400 hover:text-red-300 text-xs transition-opacity"
              >
                Delete
              </button>
            </div>
          ))
        )}
      </div>

      {completedCount > 0 && (
        <button
          onClick={handleClearCompleted}
          className="w-full text-xs text-red-400 hover:text-red-300 py-1"
        >
          Clear completed tasks
        </button>
      )}
    </div>
  );
};

export class TodoListTool {
  static Component = TodoList;
}
