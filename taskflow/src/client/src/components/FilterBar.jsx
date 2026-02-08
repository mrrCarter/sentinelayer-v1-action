/**
 * FilterBar Component
 * Provides filtering controls for the task board.
 */
import React from 'react';

const PRIORITY_OPTIONS = [
  { value: '', label: 'All Priorities' },
  { value: 'urgent', label: '🔴 Urgent' },
  { value: 'high', label: '🟠 High' },
  { value: 'medium', label: '🟡 Medium' },
  { value: 'low', label: '🟢 Low' },
];

export default function FilterBar({ filter, onChange }) {
  return (
    <div className="flex items-center gap-3 mt-3 pt-3 border-t border-gray-100">
      <span className="text-sm text-gray-500">Filters:</span>

      <select
        value={filter.priority}
        onChange={(e) => onChange({ ...filter, priority: e.target.value })}
        className="text-sm border border-gray-200 rounded-lg px-3 py-1.5 bg-white
                   focus:outline-none focus:ring-2 focus:ring-blue-500"
      >
        {PRIORITY_OPTIONS.map(opt => (
          <option key={opt.value} value={opt.value}>{opt.label}</option>
        ))}
      </select>

      {(filter.priority || filter.assignee) && (
        <button
          onClick={() => onChange({ priority: '', assignee: '' })}
          className="text-sm text-blue-600 hover:text-blue-800 underline"
        >
          Clear filters
        </button>
      )}
    </div>
  );
}

